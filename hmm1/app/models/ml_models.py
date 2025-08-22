# app/models/ml_models.py
"""
Machine Learning models for behavioral biometric authentication
"""
import numpy as np
import tensorflow as tf
from tensorflow.keras.models import Model, Sequential
from tensorflow.keras.layers import GRU, Dense, Dropout, Input, RepeatVector, TimeDistributed
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.neighbors import NearestNeighbors
from sklearn.linear_model import PassiveAggressiveClassifier
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import joblib
import logging
from typing import Dict, List, Tuple, Optional, Any
import os
from datetime import datetime

logger = logging.getLogger(__name__)

class GRUSequenceModel:
    """GRU-based model for sequential behavioral data analysis"""
    
    def __init__(self, sequence_length: int = 10, feature_dim: int = 40, 
                 hidden_units: int = 64, dropout_rate: float = 0.3):
        self.sequence_length = sequence_length
        self.feature_dim = feature_dim
        self.hidden_units = hidden_units
        self.dropout_rate = dropout_rate
        self.model = None
        self.scaler = StandardScaler()
        self.is_trained = False
        
    def build_model(self):
        """Build the GRU architecture"""
        model = Sequential([
            GRU(self.hidden_units, return_sequences=True, input_shape=(self.sequence_length, self.feature_dim)),
            Dropout(self.dropout_rate),
            GRU(self.hidden_units // 2, return_sequences=False),
            Dropout(self.dropout_rate),
            Dense(32, activation='relu'),
            Dense(1, activation='sigmoid')  # Binary classification (legitimate/anomalous)
        ])
        
        model.compile(
            optimizer='adam',
            loss='binary_crossentropy',
            metrics=['accuracy', 'precision', 'recall']
        )
        
        self.model = model
        return model
    
    def prepare_sequences(self, features: np.ndarray) -> np.ndarray:
        """Prepare sequential data for GRU training"""
        if len(features) < self.sequence_length:
            # Pad with zeros if insufficient data
            padded = np.zeros((self.sequence_length, self.feature_dim))
            padded[:len(features)] = features
            return padded.reshape(1, self.sequence_length, self.feature_dim)
        
        sequences = []
        for i in range(len(features) - self.sequence_length + 1):
            sequences.append(features[i:i + self.sequence_length])
        
        return np.array(sequences)
    
    def train(self, training_data: List[np.ndarray], labels: Optional[List[int]] = None) -> Dict[str, Any]:
        """Train the GRU model"""
        if not training_data:
            raise ValueError("No training data provided")
        
        # Combine all training sequences
        all_features = np.vstack(training_data)
        
        # Normalize features
        normalized_features = self.scaler.fit_transform(all_features)
        
        # Prepare sequences
        sequences = self.prepare_sequences(normalized_features)
        
        # For unsupervised learning, we'll use reconstruction-based approach
        if labels is None:
            # All training data is assumed to be legitimate user behavior
            labels = np.ones(len(sequences))
        
        # Build model if not already built
        if self.model is None:
            self.build_model()
        
        # Train the model
        history = self.model.fit(
            sequences, labels,
            epochs=50,
            batch_size=32,
            validation_split=0.2,
            verbose=0,
            callbacks=[
                tf.keras.callbacks.EarlyStopping(patience=10, restore_best_weights=True),
                tf.keras.callbacks.ReduceLROnPlateau(patience=5, factor=0.5)
            ]
        )
        
        self.is_trained = True
        
        return {
            'final_loss': history.history['loss'][-1],
            'final_accuracy': history.history['accuracy'][-1],
            'epochs_trained': len(history.history['loss'])
        }
    
    def predict_anomaly(self, features: np.ndarray) -> Tuple[float, float]:
        """Predict anomaly score for given features"""
        if not self.is_trained:
            return 0.5, 0.0  # Neutral score if not trained
        
        # Normalize features
        normalized_features = self.scaler.transform(features.reshape(1, -1))
        
        # Prepare sequence
        sequence = self.prepare_sequences(normalized_features)
        
        # Get prediction
        prediction = self.model.predict(sequence, verbose=0)[0][0]
        
        # Convert to anomaly score (lower prediction = higher anomaly)
        anomaly_score = 1 - prediction
        confidence = abs(prediction - 0.5) * 2  # Distance from neutral
        
        return float(anomaly_score), float(confidence)

class AutoencoderModel:
    """Autoencoder for detecting behavioral anomalies"""
    
    def __init__(self, input_dim: int = 40, encoding_dim: int = 20, 
                 hidden_layers: List[int] = [32, 16]):
        self.input_dim = input_dim
        self.encoding_dim = encoding_dim
        self.hidden_layers = hidden_layers
        self.model = None
        self.scaler = MinMaxScaler()
        self.is_trained = False
        self.reconstruction_threshold = 0.0
        
    def build_model(self):
        """Build the autoencoder architecture"""
        # Input layer
        input_layer = Input(shape=(self.input_dim,))
        
        # Encoder
        encoded = input_layer
        for units in self.hidden_layers:
            encoded = Dense(units, activation='relu')(encoded)
            encoded = Dropout(0.2)(encoded)
        
        # Bottleneck
        encoded = Dense(self.encoding_dim, activation='relu')(encoded)
        
        # Decoder
        decoded = encoded
        for units in reversed(self.hidden_layers):
            decoded = Dense(units, activation='relu')(decoded)
            decoded = Dropout(0.2)(decoded)
        
        # Output layer
        decoded = Dense(self.input_dim, activation='linear')(decoded)
        
        # Create model
        self.model = Model(input_layer, decoded)
        self.model.compile(optimizer='adam', loss='mse', metrics=['mae'])
        
        return self.model
    
    def train(self, training_data: List[np.ndarray]) -> Dict[str, Any]:
        """Train the autoencoder"""
        if not training_data:
            raise ValueError("No training data provided")
        
        # Combine all training data
        all_features = np.vstack(training_data)
        
        # Normalize features
        normalized_features = self.scaler.fit_transform(all_features)
        
        # Build model if not already built
        if self.model is None:
            self.build_model()
        
        # Train the autoencoder
        history = self.model.fit(
            normalized_features, normalized_features,
            epochs=100,
            batch_size=32,
            validation_split=0.2,
            verbose=0,
            callbacks=[
                tf.keras.callbacks.EarlyStopping(patience=15, restore_best_weights=True),
                tf.keras.callbacks.ReduceLROnPlateau(patience=7, factor=0.5)
            ]
        )
        
        # Calculate reconstruction threshold (95th percentile of training errors)
        training_predictions = self.model.predict(normalized_features, verbose=0)
        reconstruction_errors = np.mean(np.square(normalized_features - training_predictions), axis=1)
        self.reconstruction_threshold = np.percentile(reconstruction_errors, 95)
        
        self.is_trained = True
        
        return {
            'final_loss': history.history['loss'][-1],
            'reconstruction_threshold': self.reconstruction_threshold,
            'epochs_trained': len(history.history['loss'])
        }
    
    def predict_anomaly(self, features: np.ndarray) -> Tuple[float, float]:
        """Predict anomaly score based on reconstruction error"""
        if not self.is_trained:
            return 0.5, 0.0
        
        # Normalize features
        normalized_features = self.scaler.transform(features.reshape(1, -1))
        
        # Get reconstruction
        reconstruction = self.model.predict(normalized_features, verbose=0)
        
        # Calculate reconstruction error
        reconstruction_error = np.mean(np.square(normalized_features - reconstruction))
        
        # Convert to anomaly score
        anomaly_score = min(reconstruction_error / self.reconstruction_threshold, 1.0)
        confidence = min(reconstruction_error / (self.reconstruction_threshold * 2), 1.0)
        
        return float(anomaly_score), float(confidence)

class ClassicalMLEnsemble:
    """Ensemble of classical ML models for anomaly detection"""
    
    def __init__(self):
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
        self.one_class_svm = OneClassSVM(gamma='auto', nu=0.1)
        self.nearest_neighbors = NearestNeighbors(n_neighbors=5)
        self.passive_aggressive = PassiveAggressiveClassifier(random_state=42)
        
        self.scaler = StandardScaler()
        self.is_trained = False
        self.knn_threshold = 0.0
        
    def train(self, training_data: List[np.ndarray], labels: Optional[List[int]] = None) -> Dict[str, Any]:
        """Train all classical ML models"""
        if not training_data:
            raise ValueError("No training data provided")
        
        # Combine all training data
        all_features = np.vstack(training_data)
        
        # Normalize features
        normalized_features = self.scaler.fit_transform(all_features)
        
        # Train unsupervised models
        self.isolation_forest.fit(normalized_features)
        self.one_class_svm.fit(normalized_features)
        self.nearest_neighbors.fit(normalized_features)
        
        # Calculate k-NN threshold
        distances, _ = self.nearest_neighbors.kneighbors(normalized_features)
        self.knn_threshold = np.percentile(np.mean(distances, axis=1), 95)
        
        # Train supervised model if labels available
        if labels is not None:
            self.passive_aggressive.fit(normalized_features, labels)
        
        self.is_trained = True
        
        return {
            'models_trained': ['isolation_forest', 'one_class_svm', 'k_nn', 'passive_aggressive'],
            'knn_threshold': self.knn_threshold
        }
    
    def predict_anomaly(self, features: np.ndarray) -> Dict[str, Tuple[float, float]]:
        """Get anomaly predictions from all models"""
        if not self.is_trained:
            return {model: (0.5, 0.0) for model in ['isolation_forest', 'one_class_svm', 'k_nn', 'passive_aggressive']}
        
        # Normalize features
        normalized_features = self.scaler.transform(features.reshape(1, -1))
        
        results = {}
        
        # Isolation Forest
        if_score = self.isolation_forest.decision_function(normalized_features)[0]
        if_anomaly = 1 / (1 + np.exp(if_score))  # Convert to 0-1 scale
        results['isolation_forest'] = (float(if_anomaly), 0.8)
        
        # One-Class SVM
        svm_score = self.one_class_svm.decision_function(normalized_features)[0]
        svm_anomaly = 1 / (1 + np.exp(svm_score))  # Convert to 0-1 scale
        results['one_class_svm'] = (float(svm_anomaly), 0.7)
        
        # k-Nearest Neighbors
        distances, _ = self.nearest_neighbors.kneighbors(normalized_features)
        knn_distance = np.mean(distances)
        knn_anomaly = min(knn_distance / self.knn_threshold, 1.0)
        results['k_nn'] = (float(knn_anomaly), 0.6)
        
        # Passive-Aggressive (if trained)
        try:
            pa_proba = self.passive_aggressive.decision_function(normalized_features)[0]
            pa_anomaly = 1 / (1 + np.exp(pa_proba))
            results['passive_aggressive'] = (float(pa_anomaly), 0.5)
        except:
            results['passive_aggressive'] = (0.5, 0.0)
        
        return results

class BehavioralMLEnsemble:
    """Complete ensemble of all ML models for behavioral authentication"""
    
    def __init__(self, sequence_length: int = 10, feature_dim: int = 40):
        self.gru_model = GRUSequenceModel(sequence_length, feature_dim)
        self.autoencoder_model = AutoencoderModel(feature_dim)
        self.classical_ensemble = ClassicalMLEnsemble()
        
        self.is_trained = False
        self.model_weights = {
            'gru': 0.3,
            'autoencoder': 0.3,
            'isolation_forest': 0.1,
            'one_class_svm': 0.1,
            'k_nn': 0.1,
            'passive_aggressive': 0.1
        }
    
    def train(self, training_data: List[np.ndarray], labels: Optional[List[int]] = None) -> Dict[str, Any]:
        """Train all models in the ensemble"""
        logger.info(f"Training behavioral ML ensemble with {len(training_data)} samples")
        
        results = {}
        
        # Train GRU model
        try:
            gru_results = self.gru_model.train(training_data, labels)
            results['gru'] = gru_results
            logger.info("GRU model training completed")
        except Exception as e:
            logger.error(f"GRU model training failed: {e}")
            results['gru'] = {'error': str(e)}
        
        # Train Autoencoder
        try:
            ae_results = self.autoencoder_model.train(training_data)
            results['autoencoder'] = ae_results
            logger.info("Autoencoder model training completed")
        except Exception as e:
            logger.error(f"Autoencoder training failed: {e}")
            results['autoencoder'] = {'error': str(e)}
        
        # Train Classical ML Ensemble
        try:
            classical_results = self.classical_ensemble.train(training_data, labels)
            results['classical'] = classical_results
            logger.info("Classical ML ensemble training completed")
        except Exception as e:
            logger.error(f"Classical ML training failed: {e}")
            results['classical'] = {'error': str(e)}
        
        self.is_trained = True
        results['ensemble_trained'] = True
        results['timestamp'] = datetime.now().isoformat()
        
        return results
    
    def predict_anomaly(self, features: np.ndarray) -> Dict[str, Any]:
        """Get ensemble anomaly prediction"""
        if not self.is_trained:
            return {
                'ensemble_score': 0.5,
                'confidence': 0.0,
                'risk_level': 'medium',
                'individual_scores': {},
                'is_trained': False
            }
        
        individual_scores = {}
        weighted_score = 0.0
        total_confidence = 0.0
        
        # GRU prediction
        try:
            gru_score, gru_conf = self.gru_model.predict_anomaly(features)
            individual_scores['gru'] = {'score': gru_score, 'confidence': gru_conf}
            weighted_score += gru_score * self.model_weights['gru']
            total_confidence += gru_conf * self.model_weights['gru']
        except Exception as e:
            logger.error(f"GRU prediction failed: {e}")
            individual_scores['gru'] = {'error': str(e)}
        
        # Autoencoder prediction
        try:
            ae_score, ae_conf = self.autoencoder_model.predict_anomaly(features)
            individual_scores['autoencoder'] = {'score': ae_score, 'confidence': ae_conf}
            weighted_score += ae_score * self.model_weights['autoencoder']
            total_confidence += ae_conf * self.model_weights['autoencoder']
        except Exception as e:
            logger.error(f"Autoencoder prediction failed: {e}")
            individual_scores['autoencoder'] = {'error': str(e)}
        
        # Classical ML predictions
        try:
            classical_scores = self.classical_ensemble.predict_anomaly(features)
            individual_scores['classical'] = classical_scores
            
            for model_name, (score, conf) in classical_scores.items():
                weighted_score += score * self.model_weights.get(model_name, 0.1)
                total_confidence += conf * self.model_weights.get(model_name, 0.1)
        except Exception as e:
            logger.error(f"Classical ML prediction failed: {e}")
            individual_scores['classical'] = {'error': str(e)}
        
        # Determine risk level
        if weighted_score < 0.3:
            risk_level = 'low'
        elif weighted_score < 0.7:
            risk_level = 'medium'
        else:
            risk_level = 'high'
        
        return {
            'ensemble_score': float(weighted_score),
            'confidence': float(total_confidence),
            'risk_level': risk_level,
            'individual_scores': individual_scores,
            'is_trained': True,
            'timestamp': datetime.now().isoformat()
        }
    
    def save_models(self, base_path: str) -> Dict[str, str]:
        """Save all trained models"""
        saved_paths = {}
        
        # Create directory if it doesn't exist
        os.makedirs(base_path, exist_ok=True)
        
        # Save GRU model
        if self.gru_model.is_trained:
            gru_path = os.path.join(base_path, 'gru_model.h5')
            self.gru_model.model.save(gru_path)
            
            scaler_path = os.path.join(base_path, 'gru_scaler.pkl')
            joblib.dump(self.gru_model.scaler, scaler_path)
            saved_paths['gru'] = gru_path
        
        # Save Autoencoder
        if self.autoencoder_model.is_trained:
            ae_path = os.path.join(base_path, 'autoencoder_model.h5')
            self.autoencoder_model.model.save(ae_path)
            
            ae_scaler_path = os.path.join(base_path, 'ae_scaler.pkl')
            joblib.dump(self.autoencoder_model.scaler, ae_scaler_path)
            saved_paths['autoencoder'] = ae_path
        
        # Save Classical ML models
        if self.classical_ensemble.is_trained:
            classical_path = os.path.join(base_path, 'classical_ensemble.pkl')
            joblib.dump(self.classical_ensemble, classical_path)
            saved_paths['classical'] = classical_path
        
        return saved_paths
    
    def load_models(self, base_path: str) -> bool:
        """Load all trained models"""
        try:
            # Load GRU model
            gru_path = os.path.join(base_path, 'gru_model.h5')
            if os.path.exists(gru_path):
                self.gru_model.model = tf.keras.models.load_model(gru_path)
                
                scaler_path = os.path.join(base_path, 'gru_scaler.pkl')
                if os.path.exists(scaler_path):
                    self.gru_model.scaler = joblib.load(scaler_path)
                    self.gru_model.is_trained = True
            
            # Load Autoencoder
            ae_path = os.path.join(base_path, 'autoencoder_model.h5')
            if os.path.exists(ae_path):
                self.autoencoder_model.model = tf.keras.models.load_model(ae_path)
                
                ae_scaler_path = os.path.join(base_path, 'ae_scaler.pkl')
                if os.path.exists(ae_scaler_path):
                    self.autoencoder_model.scaler = joblib.load(ae_scaler_path)
                    self.autoencoder_model.is_trained = True
            
            # Load Classical ML
            classical_path = os.path.join(base_path, 'classical_ensemble.pkl')
            if os.path.exists(classical_path):
                self.classical_ensemble = joblib.load(classical_path)
            
            self.is_trained = True
            return True
            
        except Exception as e:
            logger.error(f"Failed to load models: {e}")
            return False