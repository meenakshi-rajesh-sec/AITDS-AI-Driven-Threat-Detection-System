#!/usr/bin/env python3
"""
AITDS - Supervised ML Training Module
Random Forest training on CICIDS2017 dataset
"""

import pandas as pd
import numpy as np
import pickle
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix
import warnings
warnings.filterwarnings('ignore')

class SupervisedTrainer:
    def __init__(self):
        self.project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.dataset_path = os.path.join(self.project_root, 'datasets', 'CICIDS2017', 'cicids2017_synthetic.csv')
        self.model_path = os.path.join(self.project_root, 'models', 'supervised_rf.pkl')
        self.scaler_path = os.path.join(self.project_root, 'models', 'supervised_scaler.pkl')
        
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
        
    def load_data(self):
        """Load and prepare the CICIDS2017 dataset"""
        print("🔄 Loading CICIDS2017 dataset...")
        
        if not os.path.exists(self.dataset_path):
            raise FileNotFoundError(f"Dataset not found: {self.dataset_path}")
            
        df = pd.read_csv(self.dataset_path)
        print(f"📊 Dataset loaded: {len(df)} samples")
        
        # Filter out ANOMALY - these should only be detected by unsupervised model
        df = df[df['label'] != 'ANOMALY'].copy()
        print(f"📊 After filtering ANOMALY: {len(df)} samples")
        
        # Filter to required features and label
        available_features = [f for f in self.features if f in df.columns]
        if len(available_features) != len(self.features):
            print(f"⚠️ Warning: Missing features. Available: {available_features}")
            print(f"Dataset columns: {df.columns.tolist()}")
        
        # Prepare data with available features
        X = df[available_features]
        y = df['label']  # lowercase label column
        
        # Handle missing values
        X = X.fillna(X.mean())
        
        print(f"✅ Data prepared: {X.shape[0]} samples, {X.shape[1]} features")
        print(f"🏷️ Class distribution:\n{y.value_counts()}")
        
        return X, y, available_features
    
    def train_model(self, X, y):
        """Train Random Forest classifier"""
        print("🤖 Training Random Forest classifier...")
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Train Random Forest
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            n_jobs=-1
        )
        
        self.model.fit(X_train_scaled, y_train)
        
        # Evaluate
        y_pred = self.model.predict(X_test_scaled)
        
        print("📈 Model Evaluation:")
        print(classification_report(y_test, y_pred))
        
        # Feature importance
        feature_importance = pd.DataFrame({
            'Feature': X.columns,
            'Importance': self.model.feature_importances_
        }).sort_values('Importance', ascending=False)
        
        print("\n🔍 Feature Importance:")
        print(feature_importance)
        
        return X_test_scaled, y_test, y_pred
    
    def save_model(self):
        """Save trained model and scaler"""
        print("💾 Saving model...")
        
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        
        with open(self.model_path, 'wb') as f:
            pickle.dump(self.model, f)
            
        with open(self.scaler_path, 'wb') as f:
            pickle.dump(self.scaler, f)
            
        print(f"✅ Model saved: {self.model_path}")
        print(f"✅ Scaler saved: {self.scaler_path}")
    
    def run_training(self):
        """Complete training pipeline"""
        print("🚀 Starting supervised ML training...")
        
        try:
            # Load data
            X, y, feature_names = self.load_data()
            
            # Train model
            X_test, y_test, y_pred = self.train_model(X, y)
            
            # Save model
            self.save_model()
            
            print("✅ Supervised training completed successfully!")
            
            return {
                'model': self.model,
                'scaler': self.scaler,
                'features': feature_names,
                'accuracy': np.mean(y_pred == y_test)
            }
            
        except Exception as e:
            print(f"❌ Training failed: {str(e)}")
            return None

if __name__ == "__main__":
    trainer = SupervisedTrainer()
    result = trainer.run_training()
    
    if result:
        print(f"🎯 Final accuracy: {result['accuracy']:.4f}")
    else:
        print("💥 Training failed!")
        exit(1)
