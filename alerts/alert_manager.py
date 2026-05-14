# alerts/alert_manager.py
"""
Central alert management system for AITDS
Coordinates console, file, and Discord alerts with intelligent routing
"""

import os
import sys
import time
from datetime import datetime
from typing import Dict, List, Optional, Any

# Fix relative imports when running directly
if __name__ == "__main__":
    # Add current directory to path
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    
    # Import directly
    from console_alert import send_console_alert
    from file_alert import send_file_alert, get_alert_stats, get_recent_alerts
    from discord_alert import send_discord_alert
else:
    # Normal imports when used as module
    from .console_alert import send_console_alert
    from .file_alert import send_file_alert, get_alert_stats, get_recent_alerts
    from .discord_alert import send_discord_alert


class AlertManager:
    """
    Central alert management system for AITDS
    Manages multiple alert channels with intelligent routing and filtering
    """
    
    # Configuration
    DEFAULT_CHANNELS = ["console", "file", "discord"]
    DISCORD_WEBHOOK = "https://discordapp.com/api/webhooks/YOUR_DISCORD_WEBHOOK_URL"
    
    def __init__(self, channels: Optional[List[str]] = None, 
                 enable_discord: bool = True,
                 alert_cooldown: int = 30):
        """
        Initialize Alert Manager
        
        Args:
            channels: List of alert channels to enable
            enable_discord: Whether to enable Discord alerts
            alert_cooldown: Cooldown time in seconds for same-type alerts
        """
        print("\n" + "=" * 60)
        print("🚀 INITIALIZING AITDS ALERT MANAGER")
        print("=" * 60)
        
        # Set channels
        if channels is None:
            self.channels = self.DEFAULT_CHANNELS.copy()
        else:
            self.channels = channels
        
        # Disable Discord if requested or no webhook
        if not enable_discord or not self.DISCORD_WEBHOOK:
            if "discord" in self.channels:
                self.channels.remove("discord")
                print("[!] Discord alerts disabled")
        
        # Validate Discord webhook
        self.discord_enabled = "discord" in self.channels
        if self.discord_enabled:
            if not self.DISCORD_WEBHOOK.startswith(("https://discord.com/api/webhooks/", 
                                                   "https://discordapp.com/api/webhooks/")):
                print("[!] Invalid Discord webhook format")
                self.channels.remove("discord")
                self.discord_enabled = False
        
        # Alert tracking and cooldown
        self.alert_cooldown = alert_cooldown
        self.last_alerts: Dict[str, float] = {}  # type: timestamp
        
        # Statistics
        self.stats = {
            "total_alerts_sent": 0,
            "alerts_by_channel": {channel: 0 for channel in self.channels},
            "alerts_by_severity": {},
            "start_time": time.time(),
            "last_alert_time": None
        }
        
        print(f"[✓] Alert Manager initialized")
        print(f"    Active channels: {', '.join(self.channels)}")
        print(f"    Discord enabled: {self.discord_enabled}")
        if self.discord_enabled:
            print(f"    Discord webhook: {self.DISCORD_WEBHOOK[:40]}...")
        print(f"    Alert cooldown: {alert_cooldown}s")
        print("=" * 60)
    
    def create_alert(self, detection_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert detection result to standardized alert format
        
        Args:
            detection_result: Result from hybrid_engine.analyze_single()
            
        Returns:
            Standardized alert data dictionary
        """
        # Extract basic info
        attack_type = detection_result.get("attack_type", "Unknown")
        severity = detection_result.get("severity", "MEDIUM")
        final_decision = detection_result.get("final_decision", "UNKNOWN")
        
        # Create alert data
        alert_data = {
            "timestamp": datetime.now().isoformat(),
            "system": "AITDS",
            "attack_type": attack_type,
            "severity": severity.upper(),
            "final_decision": final_decision,
            "source": detection_result.get("source", "Unknown"),
            "confidence": detection_result.get("confidence"),
            "anomaly_score": detection_result.get("anomaly_score"),
            "risk_level": detection_result.get("risk_level", 0),
            "raw_result": detection_result  # Keep original for reference
        }
        
        # Add intelligent description
        alert_data["description"] = self._generate_description(alert_data)
        
        return alert_data
    
    def _generate_description(self, alert_data: Dict[str, Any]) -> str:
        """
        Generate intelligent description based on alert type
        
        Args:
            alert_data: Alert data dictionary
            
        Returns:
            Descriptive message
        """
        attack_type = alert_data["attack_type"]
        severity = alert_data["severity"]
        decision = alert_data["final_decision"]
        
        descriptions = {
            "KNOWN_ATTACK": {
                "DoS/DDoS": f"{severity} severity DoS/DDoS attack detected. High volume traffic pattern identified.",
                "Probe/Scan": f"{severity} severity port/probe scan detected. Multiple connection attempts observed.",
                "BruteForce": f"{severity} severity brute force attempt detected. Multiple failed authentication attempts.",
                "Bot/Malware": f"{severity} severity botnet/malware activity detected. Suspicious command patterns observed.",
                "PortScan": f"{severity} severity port scan detected. Sequential port connection attempts."
            },
            "SUSPICIOUS_ANOMALY": {
                "default": f"{severity} severity anomaly detected. Unusual network behavior pattern identified - possible zero-day attack."
            },
            "NORMAL": {
                "default": "Normal network traffic pattern detected. No threats identified."
            }
        }
        
        # Get appropriate description
        if decision in descriptions:
            if attack_type in descriptions[decision]:
                return descriptions[decision][attack_type]
            elif "default" in descriptions[decision]:
                return descriptions[decision]["default"]
        
        # Fallback
        return f"{severity} severity {attack_type} detected. Decision: {decision}"
    
    def _check_cooldown(self, alert_type: str) -> bool:
        """
        Check if alert type is in cooldown period
        
        Args:
            alert_type: Type of alert to check
            
        Returns:
            True if alert should be sent (not in cooldown), False otherwise
        """
        if alert_type not in self.last_alerts:
            return True
        
        time_since_last = time.time() - self.last_alerts[alert_type]
        return time_since_last >= self.alert_cooldown
    
    def trigger_alert(self, alert_data: Dict[str, Any], 
                     channels: Optional[List[str]] = None,
                     force: bool = False) -> Dict[str, Dict[str, Any]]:
        """
        Trigger alerts through specified channels
        
        Args:
            alert_data: Alert data dictionary
            channels: List of channels to use (defaults to all active)
            force: Force alert even if in cooldown
            
        Returns:
            Dictionary with results from each channel
        """
        if channels is None:
            channels = self.channels
        
        results = {}
        alert_type = alert_data.get("attack_type", "Unknown")
        
        # Check cooldown
        if not force and not self._check_cooldown(alert_type):
            return {"cooldown": {
                "status": "skipped",
                "message": f"Alert type '{alert_type}' in cooldown ({self.alert_cooldown}s)"
            }}
        
        # Update cooldown timer
        self.last_alerts[alert_type] = time.time()
        
        # Update statistics
        self._update_stats(alert_data, channels)
        
        # Console alerts
        if "console" in channels:
            try:
                success = send_console_alert(alert_data)
                results["console"] = {
                    "status": "success" if success else "error",
                    "message": "Alert displayed in console" if success else "Console alert failed",
                    "timestamp": datetime.now().isoformat()
                }
            except Exception as e:
                results["console"] = {
                    "status": "error",
                    "message": f"Console alert error: {str(e)}",
                    "timestamp": datetime.now().isoformat()
                }
        
        # File logging
        if "file" in channels:
            try:
                file_results = send_file_alert(alert_data)
                success = all(file_results.values())
                results["file"] = {
                    "status": "success" if success else "partial",
                    "message": f"Alert logged to {len([v for v in file_results.values() if v])}/{len(file_results)} file types",
                    "details": file_results,
                    "timestamp": datetime.now().isoformat()
                }
            except Exception as e:
                results["file"] = {
                    "status": "error",
                    "message": f"File alert error: {str(e)}",
                    "timestamp": datetime.now().isoformat()
                }
        
        # Discord alerts
        if "discord" in channels and self.discord_enabled:
            try:
                success, message, response_time = send_discord_alert(alert_data, self.DISCORD_WEBHOOK)
                results["discord"] = {
                    "status": "success" if success else "error",
                    "message": message,
                    "response_time": response_time,
                    "timestamp": datetime.now().isoformat()
                }
            except Exception as e:
                results["discord"] = {
                    "status": "error",
                    "message": f"Discord alert error: {str(e)}",
                    "timestamp": datetime.now().isoformat()
                }
        elif "discord" in channels:
            results["discord"] = {
                "status": "disabled",
                "message": "Discord alerts not enabled",
                "timestamp": datetime.now().isoformat()
            }
        
        return results
    
    def trigger_from_detection(self, detection_result: Dict[str, Any],
                              channels: Optional[List[str]] = None,
                              force: bool = False) -> Dict[str, Any]:
        """
        Trigger alert directly from detection result
        
        Args:
            detection_result: Result from hybrid_engine.analyze_single()
            channels: Alert channels to use
            force: Force alert even if in cooldown
            
        Returns:
            Complete alert response with results
        """
        # Skip normal traffic
        if detection_result.get("final_decision") == "NORMAL":
            return {
                "status": "skipped",
                "reason": "Normal traffic - no alert needed",
                "decision": "NORMAL"
            }
        
        # Skip errors
        if detection_result.get("final_decision") == "ERROR":
            return {
                "status": "skipped",
                "reason": "Detection error - no alert",
                "decision": "ERROR"
            }
        
        # Create standardized alert
        alert_data = self.create_alert(detection_result)
        
        # Trigger alert
        channel_results = self.trigger_alert(alert_data, channels, force)
        
        # Prepare response
        response = {
            "status": "alerted",
            "alert_data": alert_data,
            "channel_results": channel_results,
            "timestamp": datetime.now().isoformat()
        }
        
        # Determine overall success
        success_channels = [
            name for name, result in channel_results.items()
            if result.get("status") in ["success", "partial"]
        ]
        
        if success_channels:
            response["overall_status"] = "success"
            response["message"] = f"Alert sent to {len(success_channels)} channel(s)"
        else:
            response["overall_status"] = "error"
            response["message"] = "Alert failed on all channels"
        
        return response
    
    def _update_stats(self, alert_data: Dict[str, Any], channels: List[str]):
        """Update internal statistics"""
        self.stats["total_alerts_sent"] += 1
        self.stats["last_alert_time"] = datetime.now().isoformat()
        
        # Update channel stats
        for channel in channels:
            if channel in self.stats["alerts_by_channel"]:
                self.stats["alerts_by_channel"][channel] += 1
        
        # Update severity stats
        severity = alert_data.get("severity", "UNKNOWN")
        if severity not in self.stats["alerts_by_severity"]:
            self.stats["alerts_by_severity"][severity] = 0
        self.stats["alerts_by_severity"][severity] += 1
    
    def get_status(self) -> Dict[str, Any]:
        """
        Get current alert manager status and statistics
        
        Returns:
            Status dictionary
        """
        # Get file-based statistics
        file_stats = get_alert_stats() or {}
        
        # Calculate uptime
        uptime_seconds = time.time() - self.stats["start_time"]
        uptime_str = self._format_uptime(uptime_seconds)
        
        status = {
            "system": {
                "active_channels": self.channels,
                "discord_enabled": self.discord_enabled,
                "alert_cooldown": self.alert_cooldown,
                "uptime": uptime_str,
                "uptime_seconds": uptime_seconds
            },
            "alerts": {
                "total_sent": self.stats["total_alerts_sent"],
                "by_channel": self.stats["alerts_by_channel"],
                "by_severity": self.stats["alerts_by_severity"],
                "last_alert": self.stats["last_alert_time"]
            },
            "file_stats": file_stats
        }
        
        # Calculate alert rates
        if uptime_seconds > 0:
            alerts_per_hour = (self.stats["total_alerts_sent"] / uptime_seconds) * 3600
            status["alerts"]["rate_per_hour"] = round(alerts_per_hour, 2)
        
        return status
    
    def _format_uptime(self, seconds: float) -> str:
        """Format uptime in human-readable format"""
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = int(seconds % 60)
        
        if hours > 0:
            return f"{hours}h {minutes}m {secs}s"
        elif minutes > 0:
            return f"{minutes}m {secs}s"
        else:
            return f"{secs}s"
    
    def get_recent_alerts(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get recent alerts from log files
        
        Args:
            limit: Maximum number of alerts to return
            
        Returns:
            List of recent alert entries
        """
        return get_recent_alerts(limit)
    
    def test_all_channels(self) -> Dict[str, Any]:
        """
        Test all alert channels with sample alerts
        
        Returns:
            Test results
        """
        print("\n" + "=" * 60)
        print("🔧 TESTING ALL ALERT CHANNELS")
        print("=" * 60)
        
        test_alerts = [
            {
                "timestamp": datetime.now().isoformat(),
                "system": "AITDS",
                "attack_type": "System Test - INFO",
                "severity": "INFO",
                "final_decision": "TEST",
                "source": "Alert Manager",
                "confidence": 1.0,
                "anomaly_score": 0.1,
                "risk_level": 0,
                "description": "Testing INFO level alert channel connectivity"
            },
            {
                "timestamp": datetime.now().isoformat(),
                "system": "AITDS",
                "attack_type": "System Test - MEDIUM",
                "severity": "MEDIUM",
                "final_decision": "TEST",
                "source": "Alert Manager",
                "confidence": 0.85,
                "anomaly_score": -0.35,
                "risk_level": 2,
                "description": "Testing MEDIUM severity alert channel connectivity"
            },
            {
                "timestamp": datetime.now().isoformat(),
                "system": "AITDS",
                "attack_type": "System Test - CRITICAL",
                "severity": "CRITICAL",
                "final_decision": "TEST",
                "source": "Alert Manager",
                "confidence": 0.98,
                "anomaly_score": -0.92,
                "risk_level": 4,
                "description": "Testing CRITICAL severity alert channel connectivity"
            }
        ]
        
        results = {}
        for i, alert in enumerate(test_alerts, 1):
            print(f"\nTest {i}: {alert['severity']} - {alert['attack_type']}")
            channel_results = self.trigger_alert(alert, force=True)
            results[f"test_{i}"] = channel_results
            
            # Print results
            for channel, result in channel_results.items():
                status = result.get("status", "unknown")
                symbol = "✅" if status in ["success", "partial"] else "❌"
                message = result.get("message", "")
                print(f"  {symbol} {channel}: {message}")
            
            # Small delay between tests
            if i < len(test_alerts):
                time.sleep(1)
        
        print("\n" + "=" * 60)
        print("📊 TEST SUMMARY")
        print("=" * 60)
        
        # Show status
        status = self.get_status()
        print(f"Active channels: {', '.join(status['system']['active_channels'])}")
        print(f"Total alerts sent: {status['alerts']['total_sent']}")
        print(f"Uptime: {status['system']['uptime']}")
        
        return results


# ===============================
# GLOBAL INSTANCE & CONVENIENCE FUNCTIONS
# ===============================
_global_alert_manager: Optional[AlertManager] = None

def get_alert_manager() -> AlertManager:
    """Get or create global alert manager instance"""
    global _global_alert_manager
    if _global_alert_manager is None:
        _global_alert_manager = AlertManager()
    return _global_alert_manager

def trigger_alert(alert_data: Dict[str, Any], 
                 channels: Optional[List[str]] = None,
                 force: bool = False) -> Dict[str, Dict[str, Any]]:
    """Convenience function to trigger alerts using global manager"""
    return get_alert_manager().trigger_alert(alert_data, channels, force)

def alert_from_detection(detection_result: Dict[str, Any],
                        channels: Optional[List[str]] = None,
                        force: bool = False) -> Dict[str, Any]:
    """Convenience function to trigger alert from detection result"""
    return get_alert_manager().trigger_from_detection(detection_result, channels, force)

def get_alert_status() -> Dict[str, Any]:
    """Get current alert system status"""
    return get_alert_manager().get_status()


# ===============================
# MAIN TEST
# ===============================
if __name__ == "__main__":
    print("\n" + "=" * 70)
    print("🔐 AITDS ALERT MANAGEMENT SYSTEM")
    print("=" * 70)
    
    # Initialize alert manager
    alert_manager = AlertManager()
    
    # Test all channels
    test_results = alert_manager.test_all_channels()
    
    # Show detailed status
    print("\n" + "=" * 70)
    print("📈 SYSTEM STATUS")
    print("=" * 70)
    
    status = alert_manager.get_status()
    
    print("\n⚙️ Configuration:")
    print(f"  • Active channels: {', '.join(status['system']['active_channels'])}")
    print(f"  • Discord enabled: {status['system']['discord_enabled']}")
    print(f"  • Alert cooldown: {status['system']['alert_cooldown']}s")
    print(f"  • System uptime: {status['system']['uptime']}")
    
    print("\n📊 Alert Statistics:")
    print(f"  • Total alerts sent: {status['alerts']['total_sent']}")
    
    if 'rate_per_hour' in status['alerts']:
        print(f"  • Alert rate: {status['alerts']['rate_per_hour']}/hour")
    
    if status['alerts']['by_severity']:
        print(f"  • By severity:")
        for severity, count in status['alerts']['by_severity'].items():
            print(f"    - {severity}: {count}")
    
    print(f"  • Last alert: {status['alerts']['last_alert'] or 'None'}")
    
    # Show recent alerts if any
    recent_alerts = alert_manager.get_recent_alerts(3)
    if recent_alerts:
        print(f"\n🕐 Recent alerts ({len(recent_alerts)}):")
        for i, alert in enumerate(recent_alerts, 1):
            print(f"  {i}. {alert.get('timestamp', '')[:19]} - {alert.get('type', '')} ({alert.get('severity', '')})")
    
    print("\n" + "=" * 70)
    print("✅ ALERT SYSTEM READY FOR INTEGRATION")
    print("=" * 70)
    
    print("\nUsage examples:")
    print("  from alerts.alert_manager import get_alert_manager")
    print("  alert_mgr = get_alert_manager()")
    print("  ")
    print("  # From detection result:")
    print("  result = alert_mgr.trigger_from_detection(detection_result)")
    print("  ")
    print("  # Direct alert:")
    print("  alert_data = {...}")
    print("  results = alert_mgr.trigger_alert(alert_data)")
    print("  ")
    print("  # Get status:")
    print("  status = alert_mgr.get_status()")
    print("  ")
    print("  # Get recent alerts:")
    print("  recent = alert_mgr.get_recent_alerts(10)")
    print("=" * 70)
