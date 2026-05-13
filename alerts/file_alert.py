# alerts/file_alert.py
"""
File alert module for AITDS
Saves alerts to log files with SOC-style formatting and metrics
"""

import json
import os
import csv
from datetime import datetime
import time

# Configuration
LOG_DIR = "logging"
LOG_FILE = os.path.join(LOG_DIR, "alerts.log")
CSV_FILE = os.path.join(LOG_DIR, "alerts.csv")
METRICS_FILE = os.path.join(LOG_DIR, "metrics.json")

def _ensure_log_directory():
    """Ensure logging directory exists"""
    os.makedirs(LOG_DIR, exist_ok=True)

def send_file_alert(alert_data):
    """
    Saves alert to multiple file formats (SOC-style logging)
    
    Args:
        alert_data (dict): Dictionary containing alert information
        
    Returns:
        dict: Results for each log type
    """
    _ensure_log_directory()
    
    results = {
        "json_log": False,
        "csv_log": False,
        "metrics": False
    }
    
    try:
        # 1. Prepare standardized log entry
        log_entry = {
            "timestamp": alert_data.get("timestamp", datetime.now().isoformat()),
            "system": alert_data.get("system", "AITDS"),
            "type": alert_data.get("attack_type", "Unknown"),
            "severity": alert_data.get("severity", "MEDIUM"),
            "decision": alert_data.get("final_decision", "Unknown"),
            "source": alert_data.get("source", "Unknown"),
            "confidence": alert_data.get("confidence"),
            "anomaly_score": alert_data.get("anomaly_score"),
            "risk_level": alert_data.get("risk_level", 0),
            "description": alert_data.get("description")
        }
        
        # Remove None values
        log_entry = {k: v for k, v in log_entry.items() if v is not None}
        
        # 2. Save to JSON log (structured, for machines)
        with open(LOG_FILE, "a") as f:
            json.dump(log_entry, f)
            f.write("\n")
        results["json_log"] = True
        
        # 3. Save to CSV log (for spreadsheets/SIEM)
        csv_exists = os.path.exists(CSV_FILE)
        with open(CSV_FILE, "a", newline='') as f:
            writer = csv.writer(f)
            
            # Write header if file doesn't exist
            if not csv_exists:
                writer.writerow([
                    "timestamp", "system", "type", "severity", "decision",
                    "source", "confidence", "anomaly_score", "risk_level",
                    "description"
                ])
            
            # Write data row
            writer.writerow([
                log_entry.get("timestamp", ""),
                log_entry.get("system", ""),
                log_entry.get("type", ""),
                log_entry.get("severity", ""),
                log_entry.get("decision", ""),
                log_entry.get("source", ""),
                log_entry.get("confidence", ""),
                log_entry.get("anomaly_score", ""),
                log_entry.get("risk_level", ""),
                log_entry.get("description", "")
            ])
        results["csv_log"] = True
        
        # 4. Update metrics
        _update_metrics(alert_data)
        results["metrics"] = True
        
        return results
        
    except Exception as e:
        print(f"[!] File alert error: {e}")
        return results

def _update_metrics(alert_data):
    """
    Update alert metrics statistics
    
    Args:
        alert_data (dict): Alert data to update metrics with
    """
    try:
        # Load existing metrics or create new
        metrics = {}
        if os.path.exists(METRICS_FILE):
            try:
                with open(METRICS_FILE, "r") as f:
                    metrics = json.load(f)
            except:
                metrics = {}
        
        # Initialize metrics structure if empty
        if not metrics:
            metrics = {
                "total_alerts": 0,
                "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "NONE": 0},
                "by_type": {},
                "by_source": {},
                "by_decision": {},
                "timeline": [],
                "start_time": time.time(),
                "last_alert": None
            }
        
        # Update metrics
        metrics["total_alerts"] = metrics.get("total_alerts", 0) + 1
        
        severity = alert_data.get("severity", "MEDIUM").upper()
        if severity in metrics["by_severity"]:
            metrics["by_severity"][severity] += 1
        
        alert_type = alert_data.get("attack_type", "Unknown")
        metrics["by_type"][alert_type] = metrics["by_type"].get(alert_type, 0) + 1
        
        source = alert_data.get("source", "Unknown")
        metrics["by_source"][source] = metrics["by_source"].get(source, 0) + 1
        
        decision = alert_data.get("final_decision", "Unknown")
        metrics["by_decision"][decision] = metrics["by_decision"].get(decision, 0) + 1
        
        # Add to timeline (keep last 100 entries)
        timeline_entry = {
            "timestamp": alert_data.get("timestamp", datetime.now().isoformat()),
            "type": alert_type,
            "severity": severity
        }
        metrics.setdefault("timeline", []).append(timeline_entry)
        if len(metrics["timeline"]) > 100:
            metrics["timeline"] = metrics["timeline"][-100:]
        
        metrics["last_alert"] = alert_data.get("timestamp", datetime.now().isoformat())
        metrics["uptime_seconds"] = time.time() - metrics.get("start_time", time.time())
        
        # Calculate hourly rate
        uptime_hours = metrics["uptime_seconds"] / 3600
        if uptime_hours > 0:
            metrics["alerts_per_hour"] = metrics["total_alerts"] / uptime_hours
        
        # Save updated metrics
        with open(METRICS_FILE, "w") as f:
            json.dump(metrics, f, indent=2, default=str)
            
    except Exception as e:
        print(f"[!] Metrics update error: {e}")

def get_alert_stats():
    """
    Get alert statistics
    
    Returns:
        dict: Alert statistics or None if error
    """
    try:
        if os.path.exists(METRICS_FILE):
            with open(METRICS_FILE, "r") as f:
                return json.load(f)
        return None
    except Exception as e:
        print(f"[!] Error reading metrics: {e}")
        return None

def get_recent_alerts(limit=10):
    """
    Get recent alerts from log file
    
    Args:
        limit (int): Maximum number of alerts to return
        
    Returns:
        list: Recent alert entries
    """
    alerts = []
    try:
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, "r") as f:
                lines = f.readlines()[-limit:]  # Get last 'limit' lines
                
            for line in lines:
                try:
                    alert = json.loads(line.strip())
                    alerts.append(alert)
                except:
                    continue
                    
            # Reverse to show newest first
            alerts.reverse()
    except Exception as e:
        print(f"[!] Error reading recent alerts: {e}")
    
    return alerts

def clear_logs():
    """
    Clear all log files (for testing/reset)
    
    Returns:
        dict: Results of clearing operations
    """
    results = {}
    files_to_clear = [LOG_FILE, CSV_FILE, METRICS_FILE]
    
    for filepath in files_to_clear:
        try:
            if os.path.exists(filepath):
                os.remove(filepath)
                results[os.path.basename(filepath)] = "cleared"
            else:
                results[os.path.basename(filepath)] = "not_found"
        except Exception as e:
            results[os.path.basename(filepath)] = f"error: {str(e)}"
    
    return results

def test_file_alert():
    """Test function for file alerts"""
    print("\n" + "=" * 60)
    print("TESTING FILE ALERTS")
    print("=" * 60)
    
    # Clear old logs for clean test
    print("\n[1] Clearing old logs...")
    clear_results = clear_logs()
    for file, result in clear_results.items():
        print(f"   {file}: {result}")
    
    # Test alerts
    test_alerts = [
        {
            "timestamp": datetime.now().isoformat(),
            "system": "AITDS",
            "attack_type": "DoS Attack",
            "severity": "CRITICAL",
            "final_decision": "KNOWN_ATTACK",
            "source": "Supervised Model",
            "confidence": 0.97,
            "anomaly_score": -0.89,
            "risk_level": 4,
            "description": "High volume traffic flood detected"
        },
        {
            "timestamp": datetime.now().isoformat(),
            "system": "AITDS",
            "attack_type": "Port Scan",
            "severity": "MEDIUM",
            "final_decision": "SUSPICIOUS_ANOMALY",
            "source": "Unsupervised Model",
            "confidence": None,
            "anomaly_score": -0.42,
            "risk_level": 2,
            "description": "Multiple port connection attempts"
        }
    ]
    
    print("\n[2] Saving test alerts...")
    for i, alert in enumerate(test_alerts, 1):
        print(f"   Alert {i}: {alert['attack_type']}")
        results = send_file_alert(alert)
        for log_type, success in results.items():
            status = "✅" if success else "❌"
            print(f"     {status} {log_type}")
    
    print("\n[3] Checking saved logs...")
    
    # Check JSON log
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            lines = f.readlines()
        print(f"   JSON log: {len(lines)} alerts")
        for i, line in enumerate(lines, 1):
            alert = json.loads(line.strip())
            print(f"     {i}. {alert['timestamp']} - {alert['type']} ({alert['severity']})")
    
    # Check CSV log
    if os.path.exists(CSV_FILE):
        with open(CSV_FILE, "r") as f:
            reader = csv.reader(f)
            rows = list(reader)
        print(f"   CSV log: {len(rows)-1 if rows else 0} alerts (with header)")
    
    # Check metrics
    stats = get_alert_stats()
    if stats:
        print(f"\n   Metrics:")
        print(f"     Total alerts: {stats.get('total_alerts', 0)}")
        print(f"     By severity: {stats.get('by_severity', {})}")
        print(f"     Uptime: {stats.get('uptime_seconds', 0):.0f} seconds")
    
    print("\n[4] Testing recent alerts retrieval...")
    recent = get_recent_alerts(limit=5)
    print(f"   Recent alerts retrieved: {len(recent)}")
    
    print("\n" + "=" * 60)
    print("FILE ALERT TEST COMPLETE")
    print(f"Logs saved to: {LOG_DIR}/")
    print("=" * 60)

if __name__ == "__main__":
    test_file_alert()
