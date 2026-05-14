# alerts/discord_alert.py
"""
Discord alert module for AITDS
Sends real-time alerts to Discord channels via webhooks
"""

import requests
import time
from datetime import datetime

def send_discord_alert(alert_data, webhook_url):
    """
    Sends formatted alert to Discord channel via webhook
    
    Args:
        alert_data (dict): Dictionary containing alert information
        webhook_url (str): Discord webhook URL
        
    Returns:
        tuple: (success(bool), message(str), response_time(float))
    """
    if not webhook_url:
        return False, "No webhook URL provided", 0.0
    
    # Accept both discord.com and discordapp.com formats
    valid_prefixes = [
        "https://discord.com/api/webhooks/",
        "https://discordapp.com/api/webhooks/"
    ]
    
    if not any(webhook_url.startswith(prefix) for prefix in valid_prefixes):
        return False, "Invalid Discord webhook URL format", 0.0
    
    start_time = time.time()
    
    try:
        # Severity to Discord color mapping
        severity_colors = {
            "CRITICAL": 0xFF0000,  # Red
            "HIGH": 0xFFA500,      # Orange
            "MEDIUM": 0xFFFF00,    # Yellow
            "LOW": 0x00FF00,       # Green
            "NONE": 0x808080,      # Gray
            "INFO": 0x7289DA       # Blurple (Discord default)
        }
        
        severity = alert_data.get("severity", "MEDIUM").upper()
        color = severity_colors.get(severity, 0x808080)
        
        # Get timestamp
        timestamp = alert_data.get("timestamp", datetime.now().isoformat())
        
        # Format timestamp for Discord
        try:
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            discord_timestamp = dt.isoformat()
        except:
            discord_timestamp = datetime.now().isoformat()
        
        # Create rich embed for Discord
        embed = {
            "title": f"🚨 {_get_alert_emoji(severity)} AITDS Security Alert",
            "description": f"**{alert_data.get('attack_type', 'Unknown')}**",
            "color": color,
            "timestamp": discord_timestamp,
            "fields": [],
            "footer": {
                "text": "AITDS Threat Detection System",
                "icon_url": "https://img.icons8.com/color/96/000000/security-shield.png"
            },
            "thumbnail": {
                "url": _get_severity_icon(severity)
            }
        }
        
        # Add severity field
        embed["fields"].append({
            "name": "Severity",
            "value": f"**{severity}**",
            "inline": True
        })
        
        # Add source field
        embed["fields"].append({
            "name": "Source",
            "value": alert_data.get("source", "Unknown"),
            "inline": True
        })
        
        # Add decision field
        decision = alert_data.get("final_decision", "Unknown")
        embed["fields"].append({
            "name": "Decision",
            "value": decision,
            "inline": True
        })
        
        # Add confidence if available
        confidence = alert_data.get("confidence")
        if confidence is not None:
            confidence_str = f"{confidence:.1%}" if isinstance(confidence, (int, float)) else str(confidence)
            embed["fields"].append({
                "name": "Confidence",
                "value": confidence_str,
                "inline": True
            })
        
        # Add anomaly score if available
        anomaly_score = alert_data.get("anomaly_score")
        if anomaly_score is not None:
            score_display = f"`{anomaly_score:.4f}`"
            if anomaly_score < -0.5:
                score_display = f"🔴 {score_display}"
            elif anomaly_score < -0.2:
                score_display = f"🟡 {score_display}"
            else:
                score_display = f"🟢 {score_display}"
            
            embed["fields"].append({
                "name": "Anomaly Score",
                "value": score_display,
                "inline": True
            })
        
        # Add risk level
        risk_level = alert_data.get("risk_level", 0)
        risk_bar = "🔴" * min(risk_level, 4) + "⚪" * (4 - min(risk_level, 4))
        embed["fields"].append({
            "name": "Risk Level",
            "value": f"{risk_bar} ({risk_level}/4)",
            "inline": True
        })
        
        # Add description if available
        description = alert_data.get("description")
        if description and len(description) > 0:
            # Truncate if too long for Discord
            if len(description) > 1000:
                description = description[:997] + "..."
            embed["fields"].append({
                "name": "Description",
                "value": description,
                "inline": False
            })
        
        # Prepare payload
        payload = {
            "embeds": [embed],
            "username": "AITDS Security Bot",
            "avatar_url": "https://img.icons8.com/color/96/000000/security-shield.png",
            "attachments": []
        }
        
        # Add @mentions for critical alerts
        if severity == "CRITICAL":
            payload["content"] = "@here **CRITICAL ALERT** - Immediate attention required!"
        
        # Send to Discord
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "AITDS-Security-System/1.0"
        }
        
        response = requests.post(
            webhook_url,
            json=payload,
            headers=headers,
            timeout=15  # 15 second timeout
        )
        
        response_time = time.time() - start_time
        
        # Check response
        if response.status_code in [200, 204]:
            return True, f"Alert sent successfully ({response_time:.2f}s)", response_time
        elif response.status_code == 429:
            # Rate limited - extract retry time
            retry_after = response.headers.get('Retry-After', 5)
            return False, f"Rate limited. Try again in {retry_after} seconds", response_time
        else:
            return False, f"Discord API error: {response.status_code} - {response.text[:100]}", response_time
            
    except requests.exceptions.Timeout:
        response_time = time.time() - start_time
        return False, f"Request timeout after {response_time:.1f}s", response_time
    except requests.exceptions.ConnectionError:
        response_time = time.time() - start_time
        return False, "Connection error - check network", response_time
    except Exception as e:
        response_time = time.time() - start_time
        return False, f"Error: {str(e)}", response_time


def _get_alert_emoji(severity):
    """Get appropriate emoji for alert severity"""
    emoji_map = {
        "CRITICAL": "🔥",
        "HIGH": "⚠️",
        "MEDIUM": "🚨",
        "LOW": "📢",
        "NONE": "ℹ️",
        "INFO": "📝"
    }
    return emoji_map.get(severity.upper(), "🚨")


def _get_severity_icon(severity):
    """Get icon URL for severity level"""
    icon_map = {
        "CRITICAL": "https://img.icons8.com/color/96/000000/high-priority.png",
        "HIGH": "https://img.icons8.com/color/96/000000/medium-priority.png",
        "MEDIUM": "https://img.icons8.com/color/96/000000/low-priority.png",
        "LOW": "https://img.icons8.com/color/96/000000/info.png",
        "NONE": "https://img.icons8.com/color/96/000000/info.png"
    }
    return icon_map.get(severity.upper(), "https://img.icons8.com/color/96/000000/security-shield.png")


def test_discord_webhook(webhook_url):
    """
    Test Discord webhook connectivity
    
    Args:
        webhook_url (str): Discord webhook URL to test
        
    Returns:
        dict: Test results
    """
    print("\n" + "=" * 60)
    print("TESTING DISCORD WEBHOOK")
    print("=" * 60)
    
    if not webhook_url:
        return {"status": "error", "message": "No webhook URL provided"}
    
    test_alert = {
        "timestamp": datetime.now().isoformat(),
        "attack_type": "Discord Webhook Test",
        "severity": "INFO",
        "final_decision": "TEST",
        "source": "AITDS Test Suite",
        "confidence": 1.0,
        "description": "This is a test message to verify Discord webhook connectivity.",
        "risk_level": 0
    }
    
    print(f"Webhook URL: {webhook_url[:50]}...")
    print("Sending test alert...")
    
    success, message, response_time = send_discord_alert(test_alert, webhook_url)
    
    result = {
        "status": "success" if success else "error",
        "message": message,
        "response_time": f"{response_time:.2f}s",
        "timestamp": datetime.now().isoformat()
    }
    
    if success:
        print(f"✅ {message}")
    else:
        print(f"❌ {message}")
    
    print("=" * 60)
    return result


def send_bulk_alerts(alerts, webhook_url, delay=1.0):
    """
    Send multiple alerts with delay between them
    
    Args:
        alerts (list): List of alert dictionaries
        webhook_url (str): Discord webhook URL
        delay (float): Delay between alerts in seconds
        
    Returns:
        list: Results for each alert sent
    """
    results = []
    
    for i, alert in enumerate(alerts, 1):
        print(f"Sending alert {i}/{len(alerts)}: {alert.get('attack_type', 'Unknown')}")
        
        success, message, response_time = send_discord_alert(alert, webhook_url)
        
        results.append({
            "index": i,
            "alert_type": alert.get("attack_type", "Unknown"),
            "success": success,
            "message": message,
            "response_time": response_time
        })
        
        if success:
            print(f"  ✅ Sent ({response_time:.2f}s)")
        else:
            print(f"  ❌ Failed: {message}")
        
        # Add delay between alerts (except after last one)
        if i < len(alerts):
            time.sleep(delay)
    
    # Summary
    successful = sum(1 for r in results if r["success"])
    print(f"\n📊 Summary: {successful}/{len(alerts)} alerts sent successfully")
    
    return results


# ===============================
# MAIN TEST WITH YOUR WEBHOOK
# ===============================
if __name__ == "__main__":
    # YOUR DISCORD WEBHOOK
    YOUR_WEBHOOK = "https://discordapp.com/api/webhooks/YOUR_WEBHOOK_URL"
    
    # Test the webhook
    test_discord_webhook(YOUR_WEBHOOK)
    
    # Ask if user wants to send sample alerts
    print("\n" + "=" * 60)
    test_choice = input("Send sample alerts to Discord? (y/n): ").strip().lower()
    
    if test_choice == 'y':
        print("\nSending sample alerts...")
        print("-" * 40)
        
        sample_alerts = [
            {
                "timestamp": datetime.now().isoformat(),
                "attack_type": "DoS Attack Detected",
                "severity": "CRITICAL",
                "final_decision": "KNOWN_ATTACK",
                "source": "Supervised Model",
                "confidence": 0.98,
                "anomaly_score": -0.92,
                "risk_level": 4,
                "description": "Massive traffic flood from 150+ IP addresses detected. Packet rate exceeding 12,500/sec. Immediate mitigation required."
            },
            {
                "timestamp": datetime.now().isoformat(),
                "attack_type": "Suspicious Port Scan",
                "severity": "MEDIUM",
                "final_decision": "SUSPICIOUS_ANOMALY",
                "source": "Unsupervised Model",
                "confidence": None,
                "anomaly_score": -0.45,
                "risk_level": 2,
                "description": "Sequential port connection attempts detected on multiple closed ports (22, 80, 443, 3389). Source IP: 192.168.1.50"
            },
            {
                "timestamp": datetime.now().isoformat(),
                "attack_type": "Brute Force Attempt",
                "severity": "HIGH",
                "final_decision": "KNOWN_ATTACK",
                "source": "Supervised Model",
                "confidence": 0.87,
                "anomaly_score": -0.67,
                "risk_level": 3,
                "description": "Multiple failed SSH login attempts detected from same IP address (192.168.1.100). 15 failed attempts in 2 minutes."
            },
            {
                "timestamp": datetime.now().isoformat(),
                "attack_type": "System Online",
                "severity": "INFO",
                "final_decision": "SYSTEM_INFO",
                "source": "AITDS System",
                "confidence": 1.0,
                "anomaly_score": 0.1,
                "risk_level": 0,
                "description": "AITDS Threat Detection System is now online and monitoring network traffic."
            }
        ]
        
        results = send_bulk_alerts(sample_alerts, YOUR_WEBHOOK, delay=2.0)
        
        print("\n" + "=" * 60)
        print("🎉 DISCORD ALERT TEST COMPLETE!")
        print("Check your Discord channel for the alerts!")
        print("=" * 60)
        
    else:
        print("\n" + "=" * 60)
        print("Test completed. No sample alerts sent.")
        print("Your webhook is ready to use with AITDS!")
        print("=" * 60)
