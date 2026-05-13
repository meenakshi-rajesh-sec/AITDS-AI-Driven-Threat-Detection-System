#!/usr/bin/env python3
"""
AITDS - Anomaly Generator
Simulates various attack patterns for testing the detection system
"""

import time
import threading
import random
import socket
import os
import sys
from datetime import datetime
import json

try:
    from scapy.all import IP, TCP, UDP, ICMP, send, sr1, RandShort
except ImportError:
    print("❌ Scapy not installed. Install with: pip install scapy")
    exit(1)

class AnomalyGenerator:
    """Generates realistic attack traffic patterns"""
    
    def __init__(self, target_ip="127.0.0.1", target_ports=[80, 443, 22]):
        self.target_ip = target_ip
        self.target_ports = target_ports
        self.is_running = False
        self.attack_threads = []
        
        print(f"🎯 Target: {target_ip}")
        print(f"🔌 Target ports: {target_ports}")
    
    def _get_source_ip(self):
        """Get source IP for packets"""
        try:
            # Create a socket to find local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            source_ip = s.getsockname()[0]
            s.close()
            return source_ip
        except:
            return "192.168.1.100"
    
    def _dos_attack(self, duration=30, intensity="medium"):
        """Generate DoS attack traffic"""
        print(f"🚨 Starting DoS attack - {intensity} intensity for {duration}s")
        
        source_ip = self._get_source_ip()
        target_port = random.choice(self.target_ports)
        
        # Intensity settings
        if intensity == "low":
            packet_rate = 10  # packets per second
            packet_size = 64
        elif intensity == "medium":
            packet_rate = 50
            packet_size = 128
        else:  # high
            packet_rate = 100
            packet_size = 256
        
        start_time = time.time()
        packet_count = 0
        
        while self.is_running and (time.time() - start_time) < duration:
            try:
                # Create TCP SYN packet
                packet = IP(src=source_ip, dst=self.target_ip) / TCP(
                    sport=RandShort(),
                    dport=target_port,
                    flags="S"
                )
                
                # Add payload
                if packet_size > 40:  # TCP header is 40 bytes
                    packet = packet / b"X" * (packet_size - 40)
                
                send(packet, verbose=False)
                packet_count += 1
                
                # Control packet rate
                time.sleep(1.0 / packet_rate)
                
            except Exception as e:
                print(f"⚠️ DoS packet error: {e}")
                time.sleep(0.1)
        
        print(f"✅ DoS attack completed - {packet_count} packets sent")
    
    def _ddos_attack(self, duration=30, source_count=5):
        """Generate DDoS attack from multiple sources"""
        print(f"🚨 Starting DDoS attack - {source_count} sources for {duration}s")
        
        target_port = random.choice(self.target_ports)
        
        def spoofed_source_attack():
            source_ip = f"192.168.{random.randint(1,254)}.{random.randint(1,254)}"
            packet_count = 0
            
            while self.is_running:
                try:
                    packet = IP(src=source_ip, dst=self.target_ip) / TCP(
                        sport=RandShort(),
                        dport=target_port,
                        flags="S"
                    )
                    
                    send(packet, verbose=False)
                    packet_count += 1
                    time.sleep(0.01)  # High rate
                    
                except Exception as e:
                    time.sleep(0.1)
        
        # Start multiple threads
        threads = []
        for i in range(source_count):
            t = threading.Thread(target=spoofed_source_attack)
            t.daemon = True
            t.start()
            threads.append(t)
            time.sleep(0.1)  # Stagger starts
        
        # Wait for duration
        time.sleep(duration)
        
        print(f"✅ DDoS attack completed")
    
    def _port_scan(self, duration=20):
        """Generate port scanning traffic"""
        print(f"🔍 Starting port scan for {duration}s")
        
        source_ip = self._get_source_ip()
        
        # Common ports to scan
        scan_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 1433, 3306, 3389, 5432, 5900]
        
        start_time = time.time()
        port_index = 0
        
        while self.is_running and (time.time() - start_time) < duration:
            try:
                target_port = scan_ports[port_index % len(scan_ports)]
                
                # TCP SYN scan
                packet = IP(src=source_ip, dst=self.target_ip) / TCP(
                    sport=RandShort(),
                    dport=target_port,
                    flags="S"
                )
                
                response = sr1(packet, timeout=1, verbose=False)
                
                if response:
                    if response.haslayer(TCP):
                        if response[TCP].flags == 0x12:  # SYN-ACK
                            print(f"📡 Port {target_port} is open")
                
                port_index += 1
                time.sleep(0.1)  # Scan rate
                
            except Exception as e:
                time.sleep(0.1)
        
        print(f"✅ Port scan completed")
    
    def _brute_force(self, duration=15, service="ssh"):
        """Generate brute force attack traffic"""
        print(f"🔓 Starting brute force attack on {service} for {duration}s")
        
        source_ip = self._get_source_ip()
        
        # Service-specific settings
        if service == "ssh":
            target_port = 22
            usernames = ["admin", "root", "user", "test", "guest"]
            passwords = ["password", "123456", "admin", "root", "test"]
        elif service == "ftp":
            target_port = 21
            usernames = ["ftp", "admin", "user", "anonymous"]
            passwords = ["password", "ftp", "admin", "anonymous"]
        else:  # http
            target_port = 80
            usernames = ["admin", "administrator", "user"]
            passwords = ["password", "admin", "123456"]
        
        start_time = time.time()
        attempt_count = 0
        
        while self.is_running and (time.time() - start_time) < duration:
            try:
                username = random.choice(usernames)
                password = random.choice(passwords)
                
                # Create connection attempt packet
                packet = IP(src=source_ip, dst=self.target_ip) / TCP(
                    sport=RandShort(),
                    dport=target_port,
                    flags="S"
                )
                
                send(packet, verbose=False)
                attempt_count += 1
                
                # Simulate login attempt delay
                time.sleep(0.5)
                
            except Exception as e:
                time.sleep(0.1)
        
        print(f"✅ Brute force attack completed - {attempt_count} attempts")
    
    def _benign_traffic(self, duration=10):
        """Generate normal/legitimate traffic"""
        print(f"🌐 Generating benign traffic for {duration}s")
        
        source_ip = self._get_source_ip()
        
        # Normal web traffic patterns
        normal_patterns = [
            {"port": 80, "packets": 5, "size": 64, "interval": 0.1},
            {"port": 443, "packets": 8, "size": 128, "interval": 0.05},
            {"port": 22, "packets": 3, "size": 64, "interval": 0.2}
        ]
        
        start_time = time.time()
        
        while self.is_running and (time.time() - start_time) < duration:
            try:
                pattern = random.choice(normal_patterns)
                
                for _ in range(pattern["packets"]):
                    packet = IP(src=source_ip, dst=self.target_ip) / TCP(
                        sport=RandShort(),
                        dport=pattern["port"],
                        flags="PA"  # PSH+ACK (data transfer)
                    )
                    
                    if pattern["size"] > 40:
                        packet = packet / b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
                    
                    send(packet, verbose=False)
                    time.sleep(pattern["interval"])
                
                time.sleep(random.uniform(1.0, 3.0))  # Think time
                
            except Exception as e:
                time.sleep(0.1)
        
        print(f"✅ Benign traffic generation completed")
    
    def start_attacks(self):
        """Start continuous attack generation"""
        if self.is_running:
            print("⚠️ Attack generator already running")
            return
        
        self.is_running = True
        print("🚀 Starting anomaly generator...")
        print("⚠️ This will generate real network traffic for testing")
        print("🛑 Press Ctrl+C to stop")
        
        try:
            attack_cycle = 0
            
            while self.is_running:
                attack_cycle += 1
                print(f"\n🔄 Attack cycle {attack_cycle}")
                
                # Random attack selection
                attack_type = random.choice([
                    'dos', 'ddos', 'port_scan', 'brute_force', 'benign'
                ])
                
                if attack_type == 'dos':
                    intensity = random.choice(['low', 'medium', 'high'])
                    self._dos_attack(duration=20, intensity=intensity)
                
                elif attack_type == 'ddos':
                    sources = random.randint(3, 8)
                    self._ddos_attack(duration=20, source_count=sources)
                
                elif attack_type == 'port_scan':
                    self._port_scan(duration=15)
                
                elif attack_type == 'brute_force':
                    service = random.choice(['ssh', 'ftp', 'http'])
                    self._brute_force(duration=15, service=service)
                
                else:  # benign
                    self._benign_traffic(duration=10)
                
                # Rest between attacks
                if self.is_running:
                    print("😴 Resting between attacks...")
                    time.sleep(random.uniform(5, 10))
        
        except KeyboardInterrupt:
            print("\n🛑 Stopping attack generator...")
        finally:
            self.is_running = False
    
    def stop_attacks(self):
        """Stop attack generation"""
        self.is_running = False
        print("🛑 Attack generator stopped")

def main():
    """Main function for standalone execution"""
    import argparse
    
    parser = argparse.ArgumentParser(description='AITDS Anomaly Generator')
    parser.add_argument('--target', default='127.0.0.1', help='Target IP address')
    parser.add_argument('--ports', nargs='+', default=[80, 443, 22], help='Target ports')
    parser.add_argument('--attack', choices=['dos', 'ddos', 'port_scan', 'brute_force', 'benign', 'all'], 
                       default='all', help='Attack type to generate')
    
    args = parser.parse_args()
    
    generator = AnomalyGenerator(target_ip=args.target, target_ports=args.ports)
    
    if args.attack == 'all':
        generator.start_attacks()
    else:
        generator.is_running = True
        
        if args.attack == 'dos':
            generator._dos_attack(duration=30)
        elif args.attack == 'ddos':
            generator._ddos_attack(duration=30)
        elif args.attack == 'port_scan':
            generator._port_scan(duration=20)
        elif args.attack == 'brute_force':
            generator._brute_force(duration=20)
        elif args.attack == 'benign':
            generator._benign_traffic(duration=15)
        
        generator.is_running = False

if __name__ == "__main__":
    main()
