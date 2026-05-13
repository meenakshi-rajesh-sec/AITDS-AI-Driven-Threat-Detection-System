# alerts/__init__.py
"""
AITDS Alert System Package
Provides centralized alert management for threat detection
"""

# This file makes the 'alerts' directory a Python package
# It defines what gets exported when someone does: from alerts import ...

# Import the main components
from .alert_manager import (
    AlertManager,
    get_alert_manager,
    trigger_alert,
    alert_from_detection,
    get_alert_status
)

from .console_alert import send_console_alert
from .file_alert import send_file_alert, get_alert_stats, get_recent_alerts
from .discord_alert import send_discord_alert, test_discord_webhook

# Package metadata
__version__ = "1.0.0"
__author__ = "AITDS Security Team"

# List of public exports (what users can import)
__all__ = [
    # Manager
    'AlertManager',
    'get_alert_manager',
    'trigger_alert',
    'alert_from_detection',
    'get_alert_status',
    
    # Channels
    'send_console_alert',
    'send_file_alert',
    'send_discord_alert',
    
    # Utilities
    'get_alert_stats',
    'get_recent_alerts',
    'test_discord_webhook'
]
