#!/usr/bin/env python3
"""
AITDS - Main Runner
Integrated AI Threat Detection System
"""

import os
import sys
import time
import threading
import signal
import argparse
from datetime import datetime

# Add src to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from config import Config
from gui_login import LoginGUI
from gui_dashboard import SOCDashboard
from detector import DetectionEngine
from live_capture import LiveCapture
from alerts import AlertManager
from train_supervised import SupervisedTrainer
from train_unsupervised import UnsupervisedTrainer

class AITDSSystem:
    """Main AITDS system controller"""
    
    def __init__(self):
        self.config = Config()
        self.config.ensure_directories()
        
        # System components
        self.detection_engine = None
        self.live_capture = None
        self.alert_manager = None
        self.dashboard = None
        self.login_gui = None
        
        # System state
        self.is_running = False
        self.user_authenticated = False
        self.username = None
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        print("🛡️ AITDS System initialized")
    
    def signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        print(f"\n🛑 Received signal {signum} - shutting down...")
        self.shutdown()
        sys.exit(0)
    
    def train_models(self):
        """Train ML models if not exists"""
        print("🤖 Checking ML models...")
        
        models_exist = (
            os.path.exists(Config.SUPERVISED_MODEL_PATH) and
            os.path.exists(Config.UNSUPERVISED_MODEL_PATH)
        )
        
        if not models_exist:
            print("📚 Training ML models...")
            
            # Train supervised model
            supervised_trainer = SupervisedTrainer()
            supervised_result = supervised_trainer.run_training()
            
            if not supervised_result:
                print("❌ Supervised training failed")
                return False
            
            # Train unsupervised model
            unsupervised_trainer = UnsupervisedTrainer()
            unsupervised_result = unsupervised_trainer.run_training()
            
            if not unsupervised_result:
                print("❌ Unsupervised training failed")
                return False
            
            print("✅ ML models trained successfully")
        else:
            print("✅ ML models found")
        
        return True
    
    def authenticate_user(self):
        """Authenticate user via login GUI"""
        print("🔐 Starting authentication...")
        
        self.login_gui = LoginGUI()
        auth_result = self.login_gui.run()
        
        if auth_result['authenticated']:
            self.user_authenticated = True
            self.username = auth_result['username']
            print(f"✅ User {self.username} authenticated")
            return True
        else:
            print("❌ Authentication failed")
            return False
    
    def initialize_components(self):
        """Initialize system components"""
        print("🔧 Initializing system components...")
        
        try:
            # Initialize alert manager
            self.alert_manager = AlertManager(discord_webhook=Config.DISCORD_WEBHOOK)
            self.alert_manager.start()
            
            # Initialize detection engine
            self.detection_engine = DetectionEngine()
            if not self.detection_engine.load_models():
                print("❌ Failed to load detection models")
                return False
            
            # Initialize live capture
            self.live_capture = LiveCapture()
            
            # Connect components
            self.detection_engine.add_alert_callback(self.on_detection_alert)
            self.detection_engine.add_alert_callback(self.alert_manager.send_alert)
            
            # Initialize dashboard
            self.dashboard = SOCDashboard(username=self.username)
            self.detection_engine.add_alert_callback(self.dashboard.add_alert)
            
            # Connect dashboard to detection engine for monitoring controls
            self.dashboard.set_detector_reference(self.detection_engine)
            
            print("✅ System components initialized")
            return True
            
        except Exception as e:
            print(f"❌ Component initialization failed: {e}")
            return False
    
    def on_detection_alert(self, alert):
        """Handle detection alerts"""
        # Update dashboard stats
        if self.dashboard:
            self.dashboard.stats = self.detection_engine.get_stats()
    
    def start_monitoring(self):
        """Start system monitoring"""
        print("🚀 Starting AITDS monitoring...")
        
        try:
            # Start detection engine
            if not self.detection_engine.start_monitoring():
                print("❌ Failed to start detection engine")
                return False
            
            # Start packet capture
            self.live_capture.start_capture()
            
            # Start flow processing
            self.is_running = True
            self.monitoring_thread = threading.Thread(target=self.monitoring_worker, daemon=True)
            self.monitoring_thread.start()
            
            print("✅ AITDS monitoring started")
            print("📊 Status: 🟢 Monitoring")
            print("⚠️ No alerts will be generated until real traffic is detected")
            
            return True
            
        except Exception as e:
            print(f"❌ Failed to start monitoring: {e}")
            return False
    
    def monitoring_worker(self):
        """Background monitoring worker"""
        print("🔍 Monitoring worker started")
        
        while self.is_running:
            try:
                # Get flows from capture
                flows = self.live_capture.get_flows()
                
                # Process flows through detection engine
                for flow in flows:
                    self.detection_engine.add_flow(flow)
                
                # Update dashboard system info
                if self.dashboard:
                    capture_status = self.live_capture.get_status()
                    detection_status = self.detection_engine.get_status()
                    
                    system_info = {
                        'engine_status': detection_status['monitoring'],
                        'capture_status': capture_status['capturing'],
                        'active_flows': capture_status['active_flows'],
                        'queue_size': detection_status['queue_size'],
                        'uptime': time.time()
                    }
                    
                    self.dashboard.update_system_info(system_info)
                    self.dashboard.stats = detection_status['stats']
                
                # Sleep to prevent high CPU usage
                time.sleep(0.5)
                
            except Exception as e:
                print(f"⚠️ Monitoring worker error: {e}")
                time.sleep(1)
        
        print("🛑 Monitoring worker stopped")
    
    def run_dashboard(self):
        """Run the dashboard GUI"""
        if self.dashboard:
            self.dashboard.run()
    
    def shutdown(self):
        """Graceful system shutdown"""
        print("🛑 Shutting down AITDS...")
        
        self.is_running = False
        
        # Stop monitoring
        if self.detection_engine:
            self.detection_engine.stop_monitoring()
        
        # Stop capture
        if self.live_capture:
            self.live_capture.stop_capture()
        
        # Stop alerts
        if self.alert_manager:
            self.alert_manager.stop()
        
        # Close dashboard
        if self.dashboard:
            try:
                if hasattr(self.dashboard, 'root') and self.dashboard.root:
                    if self.dashboard.root.winfo_exists():
                        self.dashboard.on_closing()
            except:
                pass  # GUI already closed
        
        print("✅ AITDS shutdown complete")
    
    def run(self, train_only=False):
        """Main system run method"""
        print("🚀 Starting AITDS - AI Threat Detection System")
        print("="*60)
        
        try:
            # Train models if requested
            if train_only:
                return self.train_models()
            
            # Train models if needed
            if not self.train_models():
                print("❌ Model training failed - exiting")
                return False
            
            # Authenticate user
            if not self.authenticate_user():
                print("❌ Authentication failed - exiting")
                return False
            
            # Initialize components
            if not self.initialize_components():
                print("❌ Component initialization failed - exiting")
                return False
            
            # Start monitoring
            if not self.start_monitoring():
                print("❌ Failed to start monitoring - exiting")
                return False
            
            # Run dashboard (this blocks until GUI is closed)
            print("🖥️ Launching SOC dashboard...")
            self.run_dashboard()
            
            return True
            
        except KeyboardInterrupt:
            print("\n🛑 Interrupted by user")
            return False
        except Exception as e:
            print(f"❌ System error: {e}")
            return False
        finally:
            self.shutdown()

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='AITDS - AI Threat Detection System')
    parser.add_argument('--train-only', action='store_true', help='Only train models')
    parser.add_argument('--no-gui', action='store_true', help='Run without GUI')
    parser.add_argument('--config', help='Configuration file path')
    
    args = parser.parse_args()
    
    # Load custom config if provided
    if args.config:
        Config.load_config(args.config)
    
    # Create and run system
    aitds = AITDSSystem()
    
    if args.train_only:
        success = aitds.run(train_only=True)
        sys.exit(0 if success else 1)
    elif args.no_gui:
        # Run without GUI
        print("🚀 Starting AITDS - AI Threat Detection System (No GUI Mode)")
        print("="*60)
        
        # Train models if needed
        if not aitds.train_models():
            print("❌ Model training failed - exiting")
            sys.exit(1)
        
        # Skip GUI authentication
        aitds.user_authenticated = True
        aitds.username = "admin"
        print("✅ Using default authentication (no GUI mode)")
        
        # Initialize components
        if not aitds.initialize_components():
            print("❌ Component initialization failed - exiting")
            sys.exit(1)
        
        # Start monitoring
        if not aitds.start_monitoring():
            print("❌ Failed to start monitoring - exiting")
            sys.exit(1)
        
        print("✅ AITDS monitoring started (no GUI mode)")
        print("Press Ctrl+C to stop...")
        
        try:
            # Keep running
            while aitds.is_running:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n🛑 Stopping...")
        finally:
            aitds.shutdown()
        
        sys.exit(0)
    else:
        success = aitds.run()
        sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
