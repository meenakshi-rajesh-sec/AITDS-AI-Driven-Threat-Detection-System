# alerts/console_alert.py
"""
Console alert module for AITDS
Prints colored, formatted alerts to terminal
"""

from datetime import datetime
import sys

def send_console_alert(alert_data):
    """
    Prints alert to terminal with color formatting
    
    Args:
        alert_data (dict): Dictionary containing alert information
            Required keys: attack_type, severity
            Optional keys: confidence, source, description, timestamp
    
    Returns:
        bool: True if alert printed successfully
    """
    try:
        # ANSI color codes for terminal colors
        COLORS = {
            "CRITICAL": "\033[91m",  # Bright Red
            "HIGH": "\033[93m",      # Yellow  
            "MEDIUM": "\033[96m",    # Cyan
            "LOW": "\033[92m",       # Green
            "NONE": "\033[37m",      # Light Gray
            "RESET": "\033[0m"       # Reset to default
        }
        
        # Get severity and corresponding color
        severity = alert_data.get("severity", "MEDIUM").upper()
        color = COLORS.get(severity, COLORS["MEDIUM"])
        reset = COLORS["RESET"]
        
        # Get timestamp
        timestamp = alert_data.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        
        # Build the alert display
        print("\n" + "=" * 65)
        print(f"{color}╔═══════════════════════════════════════════════════════╗{reset}")
        print(f"{color}║                 🚨 AITDS SECURITY ALERT 🚨            ║{reset}")
        print(f"{color}╚═══════════════════════════════════════════════════════╝{reset}")
        print(f"{color}│{reset} Time       : {timestamp}")
        print(f"{color}│{reset} Type       : {alert_data.get('attack_type', 'Unknown')}")
        print(f"{color}│{reset} Decision   : {alert_data.get('final_decision', 'Unknown')}")
        print(f"{color}│{reset} Severity   : {color}{severity}{reset}")
        
        # Add confidence if available
        confidence = alert_data.get("confidence")
        if confidence is not None:
            confidence_str = f"{confidence:.1%}" if isinstance(confidence, (int, float)) else str(confidence)
            print(f"{color}│{reset} Confidence : {confidence_str}")
        
        # Add anomaly score if available
        anomaly_score = alert_data.get("anomaly_score")
        if anomaly_score is not None:
            print(f"{color}│{reset} Anomaly    : {anomaly_score:.4f}")
        
        # Add source
        print(f"{color}│{reset} Source     : {alert_data.get('source', 'Unknown')}")
        
        # Add risk level
        risk_level = alert_data.get("risk_level")
        if risk_level is not None:
            risk_str = "🔴" * min(risk_level, 4) + "⚪" * (4 - min(risk_level, 4))
            print(f"{color}│{reset} Risk Level : {risk_str} ({risk_level}/4)")
        
        # Add description if available
        description = alert_data.get("description")
        if description:
            print(f"{color}│{reset}")
            print(f"{color}│{reset} Description:")
            # Wrap long description
            desc_lines = []
            words = description.split()
            current_line = ""
            for word in words:
                if len(current_line) + len(word) + 1 <= 55:
                    current_line += (" " + word) if current_line else word
                else:
                    desc_lines.append(current_line)
                    current_line = word
            if current_line:
                desc_lines.append(current_line)
            
            for line in desc_lines:
                print(f"{color}│{reset}   {line}")
        
        print(f"{color}╚═══════════════════════════════════════════════════════╝{reset}")
        print("=" * 65)
        
        # Flush output to ensure immediate display
        sys.stdout.flush()
        
        return True
        
    except Exception as e:
        print(f"[!] Console alert error: {e}")
        # Fallback to simple alert
        print(f"\n[ALERT] {alert_data.get('attack_type', 'Unknown')} - {alert_data.get('severity', 'MEDIUM')}")
        return False


def test_console_alert():
    """Test function for console alerts"""
    print("\n" + "=" * 60)
    print("TESTING CONSOLE ALERTS")
    print("=" * 60)
    
    test_alerts = [
        {
            "attack_type": "DoS/DDoS Attack",
            "severity": "CRITICAL",
            "confidence": 0.98,
            "source": "Supervised Model",
            "final_decision": "KNOWN_ATTACK",
            "anomaly_score": -0.92,
            "risk_level": 4,
            "description": "Massive traffic flood detected from multiple IP addresses with packet rate exceeding 10,000 packets/second"
        },
        {
            "attack_type": "Port Scan",
            "severity": "MEDIUM", 
            "confidence": 0.76,
            "source": "Unsupervised Model",
            "final_decision": "SUSPICIOUS_ANOMALY",
            "anomaly_score": -0.45,
            "risk_level": 2,
            "description": "Sequential port connection attempts detected on closed ports"
        },
        {
            "attack_type": "Normal Traffic",
            "severity": "NONE",
            "confidence": 0.99,
            "source": "Hybrid Consensus", 
            "final_decision": "NORMAL",
            "anomaly_score": 0.12,
            "risk_level": 0,
            "description": "Regular network traffic patterns detected"
        }
    ]
    
    for i, alert in enumerate(test_alerts, 1):
        print(f"\nTest {i}: {alert['attack_type']}")
        send_console_alert(alert)
    
    print("\n" + "=" * 60)
    print("CONSOLE ALERT TEST COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    test_console_alert()
