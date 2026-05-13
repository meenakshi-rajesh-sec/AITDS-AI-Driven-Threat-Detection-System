#!/usr/bin/env python3
"""
AITDS - Unsupervised ML Training Module
Isolation Forest training on BENIGN traffic only
"""

import pandas as pd
import numpy as np
import pickle
import os
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report
import warnings
warnings.filterwarnings('ignore')

class UnsupervisedTrainer:
    def __init__(self):
        self.project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.dataset_path = os.path.join(self.project_root, 'datasets', 'CICIDS2017', 'cicids2017_synthetic.csv')
        self.model_path = os.path.join(self.project_root, 'models', 'unsupervised_if.pkl')
        self.scaler_path = os.path.join(self.project_root, 'models', 'unsupervised_scaler.pkl')
        
        # Fixed feature set (10 features) - lowercase from new dataset
        self.features = [
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
        
        self.model = None
        self.scaler = StandardScaler()
        
    def load_benign_data(self):
        """Load only BENIGN traffic for training"""
        print("🔄 Loading BENIGN traffic for unsupervised training...")
        
        if not os.path.exists(self.dataset_path):
            raise FileNotFoundError(f"Dataset not found: {self.dataset_path}")
            
        df = pd.read_csv(self.dataset_path)
        
        # Filter only BENIGN samples
        benign_df = df[df['label'] == 'BENIGN'].copy()
        
        if len(benign_df) == 0:
            raise ValueError("No BENIGN samples found in dataset")
            
        print(f"📊 BENIGN samples loaded: {len(benign_df)}")
        
        # Filter to required features
        available_features = [f for f in self.features if f in benign_df.columns]
        if len(available_features) != len(self.features):
            print(f"⚠️ Warning: Missing features. Available: {available_features}")
            
        X = benign_df[available_features].copy()
        
        # Handle missing values
        X = X.fillna(X.mean())
        
        print(f"✅ BENIGN data prepared: {X.shape[0]} samples, {X.shape[1]} features")
        
        return X, available_features
    
    def train_model(self, X):
        """Train Isolation Forest on BENIGN traffic"""
        print("🤖 Training Isolation Forest on BENIGN traffic...")
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Train Isolation Forest
        self.model = IsolationForest(
            contamination=0.1,  # Expected 10% anomalies
            random_state=42,
            n_jobs=-1
        )
        
        self.model.fit(X_scaled)
        
        # Test on training data (should be mostly normal)
        predictions = self.model.predict(X_scaled)
        anomaly_rate = np.mean(predictions == -1)
        
        print(f"📊 Training anomaly rate: {anomaly_rate:.4f}")
        print(f"✅ Model trained successfully!")
        
        return X_scaled, predictions
    
    def save_model(self):
        """Save trained model and scaler"""
        print("💾 Saving unsupervised model...")
        
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        
        with open(self.model_path, 'wb') as f:
            pickle.dump(self.model, f)
            
        with open(self.scaler_path, 'wb') as f:
            pickle.dump(self.scaler, f)
            
        print(f"✅ Model saved: {self.model_path}")
        print(f"✅ Scaler saved: {self.scaler_path}")
    
    def run_training(self):
        """Complete training pipeline"""
        print("🚀 Starting unsupervised ML training...")
        
        try:
            # Load BENIGN data
            X, feature_names = self.load_benign_data()
            
            # Train model
            X_scaled, predictions = self.train_model(X)
            
            # Save model
            self.save_model()
            
            print("✅ Unsupervised training completed successfully!")
            
            return {
                'model': self.model,
                'scaler': self.scaler,
                'features': feature_names,
                'training_anomaly_rate': np.mean(predictions == -1)
            }
            
        except Exception as e:
            print(f"❌ Training failed: {str(e)}")
            return None

if __name__ == "__main__":
    trainer = UnsupervisedTrainer()
    result = trainer.run_training()
    
    if result:
        print(f"🎯 Training anomaly rate: {result['training_anomaly_rate']:.4f}")
    else:
        print("💥 Training failed!")
        exit(1)
