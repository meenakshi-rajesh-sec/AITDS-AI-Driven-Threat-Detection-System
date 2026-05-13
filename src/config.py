#!/usr/bin/env python3
"""
AITDS - Configuration
Central configuration management
"""

import os
import json
from typing import Dict, Any

class Config:
    """Centralized configuration for AITDS"""
    
    # Project paths
    PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    DATASETS_DIR = os.path.join(PROJECT_ROOT, 'datasets')
    MODELS_DIR = os.path.join(PROJECT_ROOT, 'models')
    LOGS_DIR = os.path.join(PROJECT_ROOT, 'logs')
    ATTACKS_DIR = os.path.join(PROJECT_ROOT, 'attacks')
    
    # Dataset configuration
    CICIDS2017_PATH = os.path.join(DATASETS_DIR, 'CICIDS2017', 'cicids2017_synthetic.csv')
    
    # Model paths
    SUPERVISED_MODEL_PATH = os.path.join(MODELS_DIR, 'supervised_rf.pkl')
    SUPERVISED_SCALER_PATH = os.path.join(MODELS_DIR, 'supervised_scaler.pkl')
    UNSUPERVISED_MODEL_PATH = os.path.join(MODELS_DIR, 'unsupervised_if.pkl')
    UNSUPERVISED_SCALER_PATH = os.path.join(MODELS_DIR, 'unsupervised_scaler.pkl')
    
    # Fixed feature set (10 features) - lowercase from new dataset
    FEATURES = [
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
    
    # Network configuration
    DEFAULT_INTERFACE = "auto"  # Auto-detect
    FLOW_TIMEOUT = 60  # seconds
    PACKET_TIMEOUT = 1  # seconds
    
    # Detection configuration
    SUPERVISED_CONFIDENCE_THRESHOLD = 0.7
    UNSUPERVISED_CONTAMINATION = 0.1
    MAX_QUEUE_SIZE = 1000
    
    # Alert configuration
    DISCORD_WEBHOOK = "https://discord.com/api/webhooks/1459445026483343647/6oVMRDzUYWgFRrSE_GUXyr-N9kxfrlgpeUJBNznXEgrkvTDbQEoFQS_lxsYjjNyspZgM"
    ALERT_HISTORY_SIZE = 1000
    
    # GUI configuration
    GUI_THEME = "dark"
    DASHBOARD_UPDATE_INTERVAL = 1  # seconds
    TIMELINE_UPDATE_INTERVAL = 5  # seconds
    
    # Training configuration
    SUPERVISED_MODEL_PARAMS = {
        'n_estimators': 100,
        'max_depth': 10,
        'random_state': 42,
        'n_jobs': -1
    }
    
    UNSUPERVISED_MODEL_PARAMS = {
        'contamination': 0.1,
        'random_state': 42,
        'n_jobs': -1
    }
    
    # Attack simulation configuration
    ATTACK_TARGET_IP = "127.0.0.1"
    ATTACK_TARGET_PORTS = [80, 443, 22]
    ATTACK_GENERATION_INTERVAL = 30  # seconds between attacks
    
    # Logging configuration
    LOG_LEVEL = "INFO"
    LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    
    # Security configuration
    USERS = {
        "admin": "admin123",
        "analyst": "analyst123", 
        "viewer": "viewer123"
    }
    
    # System configuration
    MAX_MEMORY_USAGE = "2GB"
    CPU_CORES = -1  # Use all available cores
    
    @classmethod
    def ensure_directories(cls):
        """Ensure all required directories exist"""
        directories = [
            cls.PROJECT_ROOT,
            cls.DATASETS_DIR,
            os.path.join(cls.DATASETS_DIR, 'CICIDS2017'),
            cls.MODELS_DIR,
            cls.LOGS_DIR,
            cls.ATTACKS_DIR
        ]
        
        for directory in directories:
            os.makedirs(directory, exist_ok=True)
    
    @classmethod
    def get_config_dict(cls) -> Dict[str, Any]:
        """Get configuration as dictionary"""
        return {
            'project_root': cls.PROJECT_ROOT,
            'datasets_dir': cls.DATASETS_DIR,
            'models_dir': cls.MODELS_DIR,
            'logs_dir': cls.LOGS_DIR,
            'attacks_dir': cls.ATTACKS_DIR,
            'cicids2017_path': cls.CICIDS2017_PATH,
            'features': cls.FEATURES,
            'discord_webhook': cls.DISCORD_WEBHOOK,
            'supervised_confidence_threshold': cls.SUPERVISED_CONFIDENCE_THRESHOLD,
            'unsupervised_contamination': cls.UNSUPERVISED_CONTAMINATION,
            'gui_theme': cls.GUI_THEME,
            'dashboard_update_interval': cls.DASHBOARD_UPDATE_INTERVAL,
            'attack_target_ip': cls.ATTACK_TARGET_IP,
            'attack_target_ports': cls.ATTACK_TARGET_PORTS
        }
    
    @classmethod
    def save_config(cls, filepath: str = None):
        """Save configuration to file"""
        if filepath is None:
            filepath = os.path.join(cls.PROJECT_ROOT, 'config.json')
        
        config = cls.get_config_dict()
        
        with open(filepath, 'w') as f:
            json.dump(config, f, indent=2, default=str)
        
        print(f"✅ Configuration saved to {filepath}")
    
    @classmethod
    def load_config(cls, filepath: str = None):
        """Load configuration from file"""
        if filepath is None:
            filepath = os.path.join(cls.PROJECT_ROOT, 'config.json')
        
        if not os.path.exists(filepath):
            print(f"⚠️ Config file not found: {filepath}")
            return
        
        try:
            with open(filepath, 'r') as f:
                config = json.load(f)
            
            # Update class attributes
            for key, value in config.items():
                if hasattr(cls, key.upper()):
                    setattr(cls, key.upper(), value)
            
            print(f"✅ Configuration loaded from {filepath}")
            
        except Exception as e:
            print(f"❌ Error loading config: {e}")

def main():
    """Test configuration"""
    print("🔧 Testing AITDS Configuration")
    
    # Ensure directories
    Config.ensure_directories()
    print("✅ Directories created/verified")
    
    # Get config dict
    config = Config.get_config_dict()
    print(f"📊 Configuration items: {len(config)}")
    
    # Save config
    Config.save_config()
    
    # Load config
    Config.load_config()
    
    print("✅ Configuration test completed")

if __name__ == "__main__":
    main()
