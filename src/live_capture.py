#!/usr/bin/env python3
"""
AITDS - Live Traffic Capture Module
Real-time packet capture and flow aggregation using Scapy
"""

import threading
import time
import os
from collections import defaultdict, deque
from datetime import datetime
import socket
import struct
import pickle

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list
except ImportError:
    print("❌ Scapy not installed. Install with: pip install scapy")
    exit(1)

class FlowTracker:
    """Track network flows and extract features"""
    
    def __init__(self):
        self.flows = {}
        self.flow_timeout = 60  # seconds
        self.last_cleanup = time.time()
        
        # Fixed feature set (10 features) - lowercase from new dataset
        self.feature_names = [
            'flow_duration',
            'total_fwd_packets', 
            'total_bwd_packets',
            'packet_length_mean',
            'packet_length_std',
            'protocol',
            'destination_port',
            'flow_bytes_per_sec',
            'flow_packets_per_sec',
            'connection_count'
        ]
    
    def _get_flow_key(self, packet):
        """Generate flow key from packet"""
        if IP not in packet:
            return None
            
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        
        # Get port numbers for TCP/UDP
        src_port = dst_port = 0
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            protocol = 6  # TCP
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            protocol = 17  # UDP
        elif ICMP in packet:
            protocol = 1  # ICMP
        
        # Create bidirectional flow key
        if (src_ip, src_port, dst_ip, dst_port) <= (dst_ip, dst_port, src_ip, src_port):
            return (src_ip, src_port, dst_ip, dst_port, protocol)
        else:
            return (dst_ip, dst_port, src_ip, src_port, protocol)
    
    def _update_flow(self, flow_key, packet):
        """Update flow statistics"""
        current_time = time.time()
        
        if flow_key not in self.flows:
            self.flows[flow_key] = {
                'start_time': current_time,
                'last_time': current_time,
                'fwd_packets': 0,
                'bwd_packets': 0,
                'fwd_bytes': 0,
                'bwd_bytes': 0,
                'packet_lengths': [],
                'src_ip': flow_key[0],
                'dst_ip': flow_key[2],
                'dst_port': flow_key[3],
                'protocol': flow_key[4]
            }
        
        flow = self.flows[flow_key]
        flow['last_time'] = current_time
        
        # Determine direction
        src_ip = packet[IP].src
        packet_size = len(packet)
        
        if src_ip == flow['src_ip']:
            # Forward direction
            flow['fwd_packets'] += 1
            flow['fwd_bytes'] += packet_size
        else:
            # Backward direction
            flow['bwd_packets'] += 1
            flow['bwd_bytes'] += packet_size
        
        flow['packet_lengths'].append(packet_size)
    
    def _extract_features(self, flow_key, flow):
        """Extract 10 fixed features from flow"""
        current_time = time.time()
        flow_duration = current_time - flow['start_time']
        
        if flow_duration == 0:
            flow_duration = 0.001  # Avoid division by zero
        
        total_packets = flow['fwd_packets'] + flow['bwd_packets']
        total_bytes = flow['fwd_bytes'] + flow['bwd_bytes']
        
        # Packet length statistics
        if flow['packet_lengths']:
            packet_lengths = np.array(flow['packet_lengths'])
            packet_len_mean = np.mean(packet_lengths)
            packet_len_std = np.std(packet_lengths)
        else:
            packet_len_mean = 0
            packet_len_std = 0
        
        # Calculate rates
        flow_bytes_per_sec = total_bytes / flow_duration if flow_duration > 0 else 0
        flow_packets_per_sec = total_packets / flow_duration if flow_duration > 0 else 0
        
        # Connection count (simplified - count of recent flows to same destination)
        connection_count = sum(1 for f in self.flows.values() 
                             if f['dst_ip'] == flow['dst_ip'] and 
                             current_time - f['last_time'] < 300)  # 5 minutes
        
        features = {
            'flow_duration': flow_duration,
            'total_fwd_packets': flow['fwd_packets'],
            'total_bwd_packets': flow['bwd_packets'],
            'packet_length_mean': packet_len_mean,
            'packet_length_std': packet_len_std,
            'flow_bytes_per_sec': flow_bytes_per_sec,
            'flow_packets_per_sec': flow_packets_per_sec,
            'connection_count': connection_count,
            'destination_port': flow['dst_port'],
            'protocol': flow['protocol']
        }
        
        return features
    
    def add_packet(self, packet):
        """Add packet to flow tracking"""
        flow_key = self._get_flow_key(packet)
        if flow_key:
            self._update_flow(flow_key, packet)
    
    def get_completed_flows(self):
        """Get flows that have completed (timed out)"""
        current_time = time.time()
        completed_flows = []
        
        # Clean up old flows
        if current_time - self.last_cleanup > 30:  # Cleanup every 30 seconds
            expired_keys = []
            for key, flow in self.flows.items():
                if current_time - flow['last_time'] > self.flow_timeout:
                    expired_keys.append(key)
            
            for key in expired_keys:
                flow = self.flows[key]
                features = self._extract_features(key, flow)
                features.update({
                    'src_ip': flow['src_ip'],
                    'dst_ip': flow['dst_ip'],
                    'timestamp': current_time
                })
                completed_flows.append(features)
                del self.flows[key]
            
            self.last_cleanup = current_time
        
        return completed_flows
    
    def get_flow_count(self):
        """Get current number of active flows"""
        return len(self.flows)

class LiveCapture:
    """Live packet capture with flow aggregation"""
    
    def __init__(self, interface=None):
        self.interface = interface or self._get_default_interface()
        self.flow_tracker = FlowTracker()
        self.is_capturing = False
        self.capture_thread = None
        self.completed_flows = deque(maxlen=1000)
        
        print(f"🌐 Network interface: {self.interface}")
    
    def _get_default_interface(self):
        """Get default network interface"""
        try:
            interfaces = get_if_list()
            # Filter out loopback and virtual interfaces
            for iface in interfaces:
                if not iface.startswith(('lo', 'docker', 'virbr', 'veth')):
                    return iface
            return interfaces[0] if interfaces else 'eth0'
        except:
            return 'eth0'
    
    def _packet_handler(self, packet):
        """Handle captured packets"""
        try:
            self.flow_tracker.add_packet(packet)
            
            # Check for completed flows
            completed = self.flow_tracker.get_completed_flows()
            if completed:
                self.completed_flows.extend(completed)
                
        except Exception as e:
            print(f"⚠️ Packet processing error: {e}")
    
    def start_capture(self):
        """Start packet capture in background thread"""
        if self.is_capturing:
            print("⚠️ Capture already running")
            return
        
        self.is_capturing = True
        self.capture_thread = threading.Thread(target=self._capture_worker)
        self.capture_thread.daemon = True
        self.capture_thread.start()
        
        print("🚀 Packet capture started")
    
    def _capture_worker(self):
        """Background capture worker"""
        try:
            sniff(
                iface=self.interface,
                prn=self._packet_handler,
                stop_filter=lambda x: not self.is_capturing,
                store=False  # Don't store packets in memory
            )
        except Exception as e:
            print(f"❌ Capture error: {e}")
            self.is_capturing = False
    
    def stop_capture(self):
        """Stop packet capture"""
        self.is_capturing = False
        if self.capture_thread:
            self.capture_thread.join(timeout=5)
        print("🛑 Packet capture stopped")
    
    def get_flows(self):
        """Get completed flows for analysis"""
        flows = list(self.completed_flows)
        self.completed_flows.clear()
        return flows
    
    def get_status(self):
        """Get capture status"""
        return {
            'capturing': self.is_capturing,
            'interface': self.interface,
            'active_flows': self.flow_tracker.get_flow_count(),
            'completed_flows': len(self.completed_flows)
        }

# Import numpy for feature extraction
import numpy as np

if __name__ == "__main__":
    # Test capture
    capture = LiveCapture()
    capture.start_capture()
    
    try:
        print("📡 Capturing packets... Press Ctrl+C to stop")
        while True:
            time.sleep(5)
            status = capture.get_status()
            print(f"📊 Status: {status}")
            
            flows = capture.get_flows()
            if flows:
                print(f"🔍 Processed {len(flows)} flows")
                
    except KeyboardInterrupt:
        print("\n🛑 Stopping capture...")
        capture.stop_capture()
