#!/usr/bin/env python3
"""
Individual Attack Generators for AITDS
Generates realistic network traffic for each attack type
"""

import socket
import random
import time
import sys
import os
import threading
import pandas as pd
from datetime import datetime

try:
    from scapy.all import IP, TCP, UDP, ICMP, send, sr1, RandShort
    SCAPY_AVAILABLE = True
except ImportError:
    print("❌ Scapy not installed. Install with: pip install scapy")
    SCAPY_AVAILABLE = False

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# Load dataset once for reference
dataset_path = os.path.join(os.path.dirname(__file__), '..', 'datasets', 'CICIDS2017', 'cicids2017_synthetic.csv')
try:
    df = pd.read_csv(dataset_path)
except:
    df = None
    print(f"⚠️ Could not load dataset from {dataset_path}")

class DoSGenerator:
    """Generate DoS attack traffic - High volume from single source"""
    
    def __init__(self, target_ip="127.0.0.1", duration=60):
        self.target_ip = target_ip
        self.duration = duration
        self.running = False
        self.stats = {'packets_sent': 0, 'start_time': None}
        self.samples = df[df['label'] == 'DoS'].to_dict('records') if df is not None else []
        self.file_lock = threading.Lock()
        
    def generate_flow(self):
        """Generate a DoS flow dict for direct injection"""
        if self.samples:
            sample = random.choice(self.samples).copy()
            for key in sample:
                if key != 'label' and isinstance(sample[key], (int, float)):
                    sample[key] = sample[key] * random.uniform(0.95, 1.05)
            sample['src_ip'] = f'192.168.1.{random.randint(100, 200)}'
            sample['dst_ip'] = self.target_ip
            sample['timestamp'] = datetime.now().isoformat()
            return sample
        return {}
    
    def _inject_flows(self):
        """Inject dataset flows directly to detector"""
        import json
        import os
        FLOW_FILE = '/tmp/aitds_injected_flows.jsonl'  # Use JSONL format
        while self.running and (time.time() - self.stats['start_time']) < self.duration:
            try:
                flow = self.generate_flow()
                if flow:
                    # Use lock to prevent file corruption
                    with self.file_lock:
                        # Ensure file exists with correct permissions
                        if not os.path.exists(FLOW_FILE):
                            with open(FLOW_FILE, 'w') as f:
                                pass  # Create empty file
                            os.chmod(FLOW_FILE, 0o666)  # Make it writable by all
                        # Append flow as a separate line
                        with open(FLOW_FILE, 'a') as f:
                            f.write(json.dumps(flow) + '\n')
                    self.stats['packets_sent'] += 1
                time.sleep(0.5)
            except Exception as e:
                pass
    
    def start(self):
        """Start DoS attack"""
        self.running = True
        self.stats['start_time'] = time.time()
        print(f"🚀 DoS Generator Started")
        print(f"   Target: {self.target_ip}")
        print(f"   Duration: {self.duration}s")
        print(f"   Pattern: SYN flood, high volume, single source")
        
        threads = []
        for _ in range(3):
            t = threading.Thread(target=self._inject_flows)
            t.daemon = True
            t.start()
            threads.append(t)
        return threads
    
    def stop(self):
        self.running = False
        print(f"🛑 DoS Generator Stopped. Packets sent: {self.stats['packets_sent']}")

class DDoSGenerator:
    """Generate DDoS attack traffic - Distributed high volume"""
    
    def __init__(self, target_ip="127.0.0.1", duration=60):
        self.target_ip = target_ip
        self.duration = duration
        self.running = False
        self.stats = {'packets_sent': 0, 'start_time': None}
        self.samples = df[df['label'] == 'DDoS'].to_dict('records') if df is not None else []
        self.file_lock = threading.Lock()
        
    def generate_flow(self):
        """Generate a DDoS flow dict"""
        if self.samples:
            sample = random.choice(self.samples).copy()
            for key in sample:
                if key != 'label' and isinstance(sample[key], (int, float)):
                    sample[key] = sample[key] * random.uniform(0.95, 1.05)
            sample['src_ip'] = f'192.168.{random.randint(1, 255)}.{random.randint(1, 255)}'
            sample['dst_ip'] = self.target_ip
            sample['timestamp'] = datetime.now().isoformat()
            return sample
        return {}
    
    def _inject_flows(self):
        """Inject dataset flows directly to detector"""
        import json
        import os
        FLOW_FILE = '/tmp/aitds_injected_flows.jsonl'  # Use JSONL format
        while self.running and (time.time() - self.stats['start_time']) < self.duration:
            try:
                flow = self.generate_flow()
                if flow:
                    # Use lock to prevent file corruption
                    with self.file_lock:
                        # Ensure file exists with correct permissions
                        if not os.path.exists(FLOW_FILE):
                            with open(FLOW_FILE, 'w') as f:
                                pass  # Create empty file
                            os.chmod(FLOW_FILE, 0o666)  # Make it writable by all
                        # Append flow as a separate line
                        with open(FLOW_FILE, 'a') as f:
                            f.write(json.dumps(flow) + '\n')
                    self.stats['packets_sent'] += 1
                time.sleep(0.5)
            except Exception as e:
                pass
    
    def start(self):
        """Start DDoS attack"""
        self.running = True
        self.stats['start_time'] = time.time()
        print(f"🚀 DDoS Generator Started")
        print(f"   Target: {self.target_ip}")
        print(f"   Duration: {self.duration}s")
        print(f"   Pattern: Distributed flood using dataset samples")
        
        threads = []
        for _ in range(5):
            t = threading.Thread(target=self._inject_flows)
            t.daemon = True
            t.start()
            threads.append(t)
        return threads
    
    def stop(self):
        self.running = False
        print(f"🛑 DDoS Generator Stopped. Packets sent: {self.stats['packets_sent']}")

class PortScanGenerator:
    """Generate Port Scan attack traffic"""
    
    def __init__(self, target_ip="127.0.0.1", duration=60):
        self.target_ip = target_ip
        self.duration = duration
        self.running = False
        self.stats = {'ports_scanned': 0, 'start_time': None}
        self.samples = df[df['label'] == 'PortScan'].to_dict('records') if df is not None else []
        self.file_lock = threading.Lock()
        
    def generate_flow(self):
        """Generate a PortScan flow dict"""
        if self.samples:
            sample = random.choice(self.samples).copy()
            for key in sample:
                if key != 'label' and isinstance(sample[key], (int, float)):
                    sample[key] = sample[key] * random.uniform(0.95, 1.05)
            sample['src_ip'] = f'192.168.1.{random.randint(100, 200)}'
            sample['dst_ip'] = self.target_ip
            sample['timestamp'] = datetime.now().isoformat()
            return sample
        return {}
    
    def _inject_flows(self):
        """Inject dataset flows directly to detector"""
        import json
        import os
        FLOW_FILE = '/tmp/aitds_injected_flows.jsonl'  # Use JSONL format
        while self.running and (time.time() - self.stats['start_time']) < self.duration:
            try:
                flow = self.generate_flow()
                if flow:
                    # Use lock to prevent file corruption
                    with self.file_lock:
                        # Ensure file exists with correct permissions
                        if not os.path.exists(FLOW_FILE):
                            with open(FLOW_FILE, 'w') as f:
                                pass  # Create empty file
                            os.chmod(FLOW_FILE, 0o666)  # Make it writable by all
                        # Append flow as a separate line
                        with open(FLOW_FILE, 'a') as f:
                            f.write(json.dumps(flow) + '\n')
                    self.stats['ports_scanned'] += 1
                time.sleep(0.3)
            except Exception as e:
                pass
    
    def start(self):
        """Start PortScan attack"""
        self.running = True
        self.stats['start_time'] = time.time()
        print(f"🚀 PortScan Generator Started")
        print(f"   Target: {self.target_ip}")
        print(f"   Duration: {self.duration}s")
        print(f"   Pattern: Port scan using dataset samples")
        
        threads = []
        for _ in range(3):
            t = threading.Thread(target=self._inject_flows)
            t.daemon = True
            t.start()
            threads.append(t)
        return threads
    
    def stop(self):
        self.running = False
        print(f"🛑 PortScan Generator Stopped. Ports scanned: {self.stats['ports_scanned']}")

class BruteForceGenerator:
    """Generate Brute Force attack traffic"""
    
    def __init__(self, target_ip="127.0.0.1", duration=60):
        self.target_ip = target_ip
        self.duration = duration
        self.running = False
        self.stats = {'attempts': 0, 'start_time': None}
        self.samples = df[df['label'] == 'BruteForce'].to_dict('records') if df is not None else []
        self.file_lock = threading.Lock()
        
    def generate_flow(self):
        """Generate a BruteForce flow dict"""
        if self.samples:
            sample = random.choice(self.samples).copy()
            for key in sample:
                if key != 'label' and isinstance(sample[key], (int, float)):
                    sample[key] = sample[key] * random.uniform(0.95, 1.05)
            sample['src_ip'] = f'192.168.1.{random.randint(100, 200)}'
            sample['dst_ip'] = self.target_ip
            sample['timestamp'] = datetime.now().isoformat()
            return sample
        return {}
    
    def _inject_flows(self):
        """Inject dataset flows directly to detector"""
        import json
        import os
        FLOW_FILE = '/tmp/aitds_injected_flows.jsonl'  # Use JSONL format
        while self.running and (time.time() - self.stats['start_time']) < self.duration:
            try:
                flow = self.generate_flow()
                if flow:
                    # Use lock to prevent file corruption
                    with self.file_lock:
                        # Ensure file exists with correct permissions
                        if not os.path.exists(FLOW_FILE):
                            with open(FLOW_FILE, 'w') as f:
                                pass  # Create empty file
                            os.chmod(FLOW_FILE, 0o666)  # Make it writable by all
                        # Append flow as a separate line
                        with open(FLOW_FILE, 'a') as f:
                            f.write(json.dumps(flow) + '\n')
                    self.stats['attempts'] += 1
                time.sleep(0.5)
            except Exception as e:
                pass
    
    def start(self):
        """Start BruteForce attack"""
        self.running = True
        self.stats['start_time'] = time.time()
        print(f"🚀 BruteForce Generator Started")
        print(f"   Target: {self.target_ip}")
        print(f"   Duration: {self.duration}s")
        print(f"   Pattern: Brute force using dataset samples")
        
        threads = []
        for _ in range(2):
            t = threading.Thread(target=self._inject_flows)
            t.daemon = True
            t.start()
            threads.append(t)
        return threads
    
    def stop(self):
        self.running = False
        print(f"🛑 BruteForce Generator Stopped. Attempts: {self.stats['attempts']}")

class ZeroDayAnomalyGenerator:
    """Generate Zero-Day anomaly traffic using unusual patterns"""
    
    def __init__(self, target_ip="127.0.0.1", duration=60):
        self.target_ip = target_ip
        self.duration = duration
        self.running = False
        self.stats = {'packets_sent': 0, 'start_time': None}
        self.samples = df[df['label'] == 'ANOMALY'].to_dict('records') if df is not None else []
        self.file_lock = threading.Lock()
        
    def generate_flow(self, anomaly_type="protocol"):
        """Generate a Zero-Day anomaly flow"""
        if self.samples:
            sample = random.choice(self.samples).copy()
            for key in sample:
                if key != 'label' and isinstance(sample[key], (int, float)):
                    sample[key] = sample[key] * random.uniform(0.95, 1.05)
            sample['src_ip'] = f'10.0.{random.randint(1, 255)}.{random.randint(1, 255)}'
            sample['dst_ip'] = self.target_ip
            sample['timestamp'] = datetime.now().isoformat()
            return sample
        return {}
    
    def _inject_flows(self):
        """Inject dataset flows directly to detector"""
        import json
        import os
        FLOW_FILE = '/tmp/aitds_injected_flows.jsonl'  # Use JSONL format
        while self.running and (time.time() - self.stats['start_time']) < self.duration:
            try:
                flow = self.generate_flow()
                if flow:
                    # Use lock to prevent file corruption
                    with self.file_lock:
                        # Ensure file exists with correct permissions
                        if not os.path.exists(FLOW_FILE):
                            with open(FLOW_FILE, 'w') as f:
                                pass  # Create empty file
                            os.chmod(FLOW_FILE, 0o666)  # Make it writable by all
                        # Append flow as a separate line
                        with open(FLOW_FILE, 'a') as f:
                            f.write(json.dumps(flow) + '\n')
                    self.stats['packets_sent'] += 1
                time.sleep(0.5)
            except Exception as e:
                pass
    
    def start(self, anomaly_type="protocol"):
        """Start Zero-Day anomaly generation"""
        self.running = True
        self.stats['start_time'] = time.time()
        print(f"🚀 Zero-Day Anomaly Generator Started")
        print(f"   Target: {self.target_ip}")
        print(f"   Duration: {self.duration}s")
        print(f"   Pattern: Zero-day anomaly using dataset samples")
        
        threads = []
        for _ in range(2):
            t = threading.Thread(target=self._inject_flows)
            t.daemon = True
            t.start()
            threads.append(t)
        return threads
    
    def stop(self):
        self.running = False
        print(f"🛑 Zero-Day Anomaly Generator Stopped. Packets sent: {self.stats['packets_sent']}")


def main():
    """Main function to run individual generators"""
    import argparse
    
    parser = argparse.ArgumentParser(description='AITDS Individual Attack Generators')
    parser.add_argument('type', choices=['dos', 'ddos', 'portscan', 'bruteforce', 'zeroday'],
                       help='Type of attack to generate')
    parser.add_argument('--target', default='127.0.0.1', help='Target IP address')
    parser.add_argument('--duration', type=int, default=60, help='Duration in seconds')
    
    args = parser.parse_args()
    
    generators = {
        'dos': DoSGenerator,
        'ddos': DDoSGenerator,
        'portscan': PortScanGenerator,
        'bruteforce': BruteForceGenerator,
        'zeroday': ZeroDayAnomalyGenerator
    }
    
    gen_class = generators[args.type]
    generator = gen_class(target_ip=args.target, duration=args.duration)
    
    print(f"\n{'='*60}")
    print(f"  AITDS Attack Generator: {args.type.upper()}")
    print(f"{'='*60}\n")
    
    threads = generator.start()
    
    try:
        time.sleep(args.duration)
    except KeyboardInterrupt:
        print("\n⚠️ Interrupted by user")
    finally:
        generator.stop()
        print(f"\n{'='*60}")
        print("  Attack generation complete")
        print(f"{'='*60}")

if __name__ == "__main__":
    main()
