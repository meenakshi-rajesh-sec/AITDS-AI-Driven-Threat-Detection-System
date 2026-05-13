#!/usr/bin/env python3
"""
AITDS - Alert System
Multi-channel alerting (terminal, GUI, Discord webhook)
"""

import os
import json
import requests
from datetime import datetime
import threading
import queue
import time
from typing import Dict, List, Callable

class AlertManager:
    """Centralized alert management system"""
    
    def __init__(self, discord_webhook=None):
        self.discord_webhook = discord_webhook
        self.alert_queue = queue.Queue()
        self.alert_callbacks = []
        self.is_running = False
        self.alert_thread = None
        
        # Alert statistics
        self.alert_stats = {
            'total_alerts': 0,
            'known_attacks': 0,
            'zero_day_anomalies': 0,
            'discord_sent': 0,
            'discord_failed': 0
        }
        
        # Alert history
        self.alert_history = []
        self.max_history = 1000
        
        print("🚨 Alert Manager initialized")
    
    def add_callback(self, callback: Callable):
        """Add alert callback function"""
        self.alert_callbacks.append(callback)
    
    def _create_terminal_alert(self, alert: Dict) -> str:
        """Create terminal alert message"""
        timestamp = alert['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
        source_ip = alert['source_ip']
        dest_ip = alert['dest_ip']
        dest_port = alert['dest_port']
        classification = alert['classification']
        confidence = f"{alert['confidence']:.2f}"
        threat_type = alert['threat_type']
        protocol = alert.get('protocol', 'N/A')
        flow_duration = f"{alert.get('flow_duration', 0):.2f}s"
        packet_count = alert.get('packet_count', 0)
        
        # Color coding
        if threat_type == 'KNOWN_ATTACK':
            color = "\033[91m"  # Red
            symbol = "🚨"
        elif threat_type == 'ZERO_DAY':
            color = "\033[93m"  # Yellow
            symbol = "⚠️"
        else:
            color = "\033[94m"  # Blue
            symbol = "ℹ️"
        
        reset = "\033[0m"
        
        alert_msg = (
            f"{color}{symbol} THREAT DETECTED{reset}\n"
            f"📅 Timestamp: {timestamp}\n"
            f"🎯 Source IP: {source_ip}\n"
            f"🎯 Destination IP: {dest_ip}\n"
            f"� Protocol: {protocol}\n"
            f"🚪 Destination Port: {dest_port}\n"
            f"⏱️ Flow Duration: {flow_duration}\n"
            f"📦 Packet Count: {packet_count}\n"
            f"🔍 Attack Class: {classification}\n"
            f"📊 Confidence: {confidence}\n"
            f"🏷️ Type: {threat_type}\n"
            f"{'='*50}"
        )
        
        return alert_msg
    
    def _create_discord_alert(self, alert: Dict) -> Dict:
        """Create Discord webhook payload"""
        timestamp = alert['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
        source_ip = alert['source_ip']
        dest_ip = alert['dest_ip']
        dest_port = alert['dest_port']
        classification = alert['classification']
        confidence = f"{alert['confidence']:.2f}"
        threat_type = alert['threat_type']
        protocol = alert.get('protocol', 'N/A')
        flow_duration = f"{alert.get('flow_duration', 0)}s"
        packet_count = alert.get('packet_count', 0)
        
        # Color coding for Discord
        if threat_type == 'KNOWN_ATTACK':
            color = 0xFF0000  # Red
            title = f"KNOWN ATTACK: {classification}"
        elif threat_type == 'ZERO_DAY':
            color = 0xFFAA00  # Orange/Yellow
            title = f"ZERO-DAY: {classification}"
        else:
            color = 0x00AA00  # Green
            title = "SECURITY EVENT"
        
        # Create embed with detailed fields
        embed = {
            "title": title,
            "color": color,
            "timestamp": alert['timestamp'].isoformat(),
            "fields": [
                {
                    "name": "Timestamp",
                    "value": f"`{timestamp}`",
                    "inline": False
                },
                {
                    "name": "Source IP",
                    "value": f"`{source_ip}`",
                    "inline": True
                },
                {
                    "name": "Destination IP",
                    "value": f"`{dest_ip}`",
                    "inline": True
                },
                {
                    "name": "Protocol",
                    "value": f"`{protocol}`",
                    "inline": True
                },
                {
                    "name": "Destination Port",
                    "value": f"`{dest_port}`",
                    "inline": True
                },
                {
                    "name": "Flow Duration",
                    "value": f"`{flow_duration}`",
                    "inline": True
                },
                {
                    "name": "Packet Count",
                    "value": f"`{packet_count}`",
                    "inline": True
                },
                {
                    "name": "Attack Class",
                    "value": f"`{classification}`",
                    "inline": True
                },
                {
                    "name": "Confidence",
                    "value": f"`{confidence}`",
                    "inline": True
                },
                {
                    "name": "Threat Type",
                    "value": f"`{threat_type}`",
                    "inline": True
                }
            ],
            "footer": {
                "text": "AITDS - AI Threat Detection System"
            }
        }
        
        return {
            "content": f"@here {title}",
            "embeds": [embed]
        }
    
    def _send_discord_alert(self, alert: Dict):
        """Send alert to Discord webhook"""
        if not self.discord_webhook:
            return False
        
        try:
            payload = self._create_discord_alert(alert)
            
            response = requests.post(
                self.discord_webhook,
                json=payload,
                timeout=10
            )
            
            if response.status_code == 204:
                self.alert_stats['discord_sent'] += 1
                print("✅ Discord alert sent successfully")
                return True
            else:
                self.alert_stats['discord_failed'] += 1
                print(f"⚠️ Discord alert failed: {response.status_code}")
                return False
                
        except Exception as e:
            self.alert_stats['discord_failed'] += 1
            print(f"❌ Discord alert error: {e}")
            return False
    
    def _send_terminal_alert(self, alert: Dict):
        """Send alert to terminal"""
        alert_msg = self._create_terminal_alert(alert)
        print(f"\n{alert_msg}\n")
    
    def _trigger_callbacks(self, alert: Dict):
        """Trigger all registered callbacks"""
        for callback in self.alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                print(f"⚠️ Alert callback error: {e}")
    
    def _process_alert(self, alert: Dict):
        """Process single alert"""
        try:
            # Update statistics
            self.alert_stats['total_alerts'] += 1
            
            if alert['threat_type'] == 'KNOWN_ATTACK':
                self.alert_stats['known_attacks'] += 1
            elif alert['threat_type'] == 'ZERO_DAY':
                self.alert_stats['zero_day_anomalies'] += 1
            
            # Add to history
            self.alert_history.append(alert)
            if len(self.alert_history) > self.max_history:
                self.alert_history.pop(0)
            
            # Send terminal alert
            self._send_terminal_alert(alert)
            
            # Send Discord alert
            if self.discord_webhook:
                # Send Discord in separate thread to avoid blocking
                discord_thread = threading.Thread(
                    target=self._send_discord_alert,
                    args=(alert,),
                    daemon=True
                )
                discord_thread.start()
            
            # Trigger callbacks
            self._trigger_callbacks(alert)
            
        except Exception as e:
            print(f"❌ Alert processing error: {e}")
    
    def _alert_worker(self):
        """Background alert processing worker"""
        print("🚨 Alert system started")
        
        while self.is_running:
            try:
                # Get alert from queue (timeout to allow checking is_running)
                alert = self.alert_queue.get(timeout=1.0)
                
                # Process alert
                self._process_alert(alert)
                
                # Mark task done
                self.alert_queue.task_done()
                
            except queue.Empty:
                # Queue empty, continue
                continue
            except Exception as e:
                print(f"❌ Alert worker error: {e}")
        
        print("🛑 Alert system stopped")
    
    def start(self):
        """Start alert system"""
        if self.is_running:
            print("⚠️ Alert system already running")
            return
        
        self.is_running = True
        self.alert_thread = threading.Thread(target=self._alert_worker, daemon=True)
        self.alert_thread.start()
        
        print("✅ Alert system started")
    
    def stop(self):
        """Stop alert system"""
        self.is_running = False
        if self.alert_thread:
            self.alert_thread.join(timeout=5)
        print("🛑 Alert system stopped")
    
    def send_alert(self, alert: Dict):
        """Queue alert for processing"""
        if self.is_running:
            self.alert_queue.put(alert)
        else:
            print("⚠️ Alert system not running - alert dropped")
    
    def get_stats(self) -> Dict:
        """Get alert statistics"""
        return self.alert_stats.copy()
    
    def get_recent_alerts(self, count: int = 10) -> List[Dict]:
        """Get recent alerts"""
        return self.alert_history[-count:]
    
    def clear_history(self):
        """Clear alert history"""
        self.alert_history.clear()
        print("🗑️ Alert history cleared")

class ConsoleAlert:
    """Console-based alert formatter"""
    
    @staticmethod
    def format_alert(alert: Dict) -> str:
        """Format alert for console display"""
        timestamp = alert['timestamp'].strftime('%H:%M:%S')
        source = f"{alert['source_ip']}:{alert['dest_port']}"
        classification = alert['classification']
        confidence = f"{alert['confidence']:.2f}"
        
        threat_type = alert['threat_type']
        if threat_type == 'KNOWN_ATTACK':
            icon = "🚨"
            level = "HIGH"
        elif threat_type == 'ZERO_DAY':
            icon = "⚠️"
            level = "MEDIUM"
        else:
            icon = "ℹ️"
            level = "LOW"
        
        return (
            f"{icon} [{timestamp}] {level} - {classification} "
            f"from {source} (Conf: {confidence})"
        )

class DiscordAlert:
    """Discord webhook alert sender"""
    
    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url
        self.session = requests.Session()
    
    def send(self, alert: Dict) -> bool:
        """Send alert to Discord"""
        try:
            # Create Discord embed
            timestamp = alert['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
            source = f"{alert['source_ip']}:{alert['dest_port']}"
            
            threat_type = alert['threat_type']
            if threat_type == 'KNOWN_ATTACK':
                color = 0xFF0000
                title = "🚨 KNOWN ATTACK DETECTED"
            elif threat_type == 'ZERO_DAY':
                color = 0xFFAA00
                title = "⚠️ ZERO-DAY ANOMALY DETECTED"
            else:
                color = 0x00AA00
                title = "ℹ️ SECURITY EVENT"
            
            embed = {
                "title": title,
                "color": color,
                "timestamp": alert['timestamp'].isoformat(),
                "fields": [
                    {"name": "Source", "value": f"`{source}`", "inline": True},
                    {"name": "Classification", "value": f"`{alert['classification']}`", "inline": True},
                    {"name": "Confidence", "value": f"`{alert['confidence']:.2f}`", "inline": True},
                    {"name": "Threat Type", "value": f"`{threat_type}`", "inline": True}
                ],
                "footer": {"text": "AITDS - AI Threat Detection System"}
            }
            
            response = self.session.post(
                self.webhook_url,
                json={"content": f"@here {title}", "embeds": [embed]},
                timeout=10
            )
            
            return response.status_code == 204
            
        except Exception as e:
            print(f"❌ Discord alert error: {e}")
            return False

def main():
    """Test alert system"""
    # Discord webhook URL (replace with actual)
    discord_webhook = "https://discord.com/api/webhooks/YOUR_WEBHOOK_URL"
    
    # Create alert manager
    alert_manager = AlertManager(discord_webhook=discord_webhook)
    alert_manager.start()
    
    # Test alerts
    test_alerts = [
        {
            'timestamp': datetime.now(),
            'source_ip': '192.168.1.100',
            'dest_ip': '192.168.1.1',
            'dest_port': 80,
            'classification': 'DoS',
            'threat_type': 'KNOWN_ATTACK',
            'confidence': 0.95
        },
        {
            'timestamp': datetime.now(),
            'source_ip': '10.0.0.50',
            'dest_ip': '10.0.0.1',
            'dest_port': 22,
            'classification': 'ZERO_DAY_ANOMALY',
            'threat_type': 'ZERO_DAY',
            'confidence': 0.87
        }
    ]
    
    # Send test alerts
    for alert in test_alerts:
        alert_manager.send_alert(alert)
        time.sleep(2)
    
    # Wait for processing
    time.sleep(5)
    
    # Print stats
    print("📊 Alert Statistics:")
    stats = alert_manager.get_stats()
    for key, value in stats.items():
        print(f"  {key}: {value}")
    
    alert_manager.stop()

if __name__ == "__main__":
    main()
