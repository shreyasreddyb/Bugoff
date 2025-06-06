#!/usr/bin/env python3
import os
import pickle
import json
import logging
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import classification_report

# Configuration - UPDATED to use home directory
ML_MODEL_DIR = os.path.expanduser("~/ml_models/")  # Now in user's home directory
DATA_SAMPLE_SIZE = 10000  # Number of samples to generate for training
TEST_SIZE = 0.2  # 20% of data for testing
RANDOM_STATE = 42

# Enhanced logging setup
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("model_training.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def generate_synthetic_data():
    """Generate synthetic training data for demonstration"""
    logger.info("Generating synthetic training data...")
    
    data = []
    for i in range(DATA_SAMPLE_SIZE // 2):
        # Benign files
        data.append({
            'size': np.random.randint(1000, 10000),
            'entropy': np.random.uniform(3.0, 5.0),
            'printable_ratio': np.random.uniform(0.8, 1.0),
            'is_pe': False,
            'label': 0  # benign
        })
        
        # Malicious files
        data.append({
            'size': np.random.randint(5000, 50000),
            'entropy': np.random.uniform(5.5, 7.5),
            'printable_ratio': np.random.uniform(0.3, 0.7),
            'is_pe': True,
            'label': 1  # malicious
        })
    
    return pd.DataFrame(data)

def generate_behavior_data():
    """Generate synthetic behavior data"""
    logger.info("Generating synthetic behavior data...")
    
    behaviors = []
    # Malicious behaviors
    for _ in range(DATA_SAMPLE_SIZE // 2):
        actions = np.random.choice([
            "created files",
            "modified registry",
            "accessed network",
            "injected code",
            "spawned processes",
            "created mutex",
            "accessed sensitive paths"
        ], size=3, replace=False)
        behaviors.append((" ".join(actions), 1))
    
    # Benign behaviors
    for _ in range(DATA_SAMPLE_SIZE // 2):
        actions = np.random.choice([
            "read files",
            "normal operations",
            "user activity",
            "accessed ui",
            "loaded libraries"
        ], size=2, replace=False)
        behaviors.append((" ".join(actions), 0))
    
    return behaviors

def train_file_classifier(X_train, y_train):
    """Train the file classifier model"""
    logger.info("Training file classifier...")
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        random_state=RANDOM_STATE,
        class_weight='balanced'
    )
    model.fit(X_train, y_train)
    return model

def train_behavior_classifier(texts, labels):
    """Train the behavior classifier model"""
    logger.info("Training behavior classifier...")
    
    # Vectorize text features
    vectorizer = TfidfVectorizer(max_features=1000)
    X = vectorizer.fit_transform(texts)
    
    # Train model
    model = RandomForestClassifier(
        n_estimators=50,
        max_depth=8,
        random_state=RANDOM_STATE
    )
    model.fit(X, labels)
    
    return model, vectorizer

def evaluate_model(model, X_test, y_test, model_name):
    """Evaluate model performance"""
    y_pred = model.predict(X_test)
    report = classification_report(y_test, y_pred, output_dict=True)
    
    logger.info(f"{model_name} Classification Report:")
    logger.info(f"Accuracy: {report['accuracy']:.2f}")
    logger.info(f"Precision: {report['weighted avg']['precision']:.2f}")
    logger.info(f"Recall: {report['weighted avg']['recall']:.2f}")
    logger.info(f"F1-Score: {report['weighted avg']['f1-score']:.2f}")
    
    return report

def save_models(file_model, behavior_model, vectorizer, file_report, behavior_report):
    """Save trained models and metadata with enhanced error handling"""
    try:
        # Create directory with verification
        os.makedirs(ML_MODEL_DIR, exist_ok=True)
        if not os.path.isdir(ML_MODEL_DIR):
            raise Exception(f"Failed to create directory: {ML_MODEL_DIR}")
        
        # Define all paths
        model_files = {
            "file_classifier.pkl": file_model,
            "behavior_model.pkl": behavior_model,
            "vectorizer.pkl": vectorizer
        }
        
        # Save all models
        for filename, obj in model_files.items():
            path = os.path.join(ML_MODEL_DIR, filename)
            with open(path, "wb") as f:
                pickle.dump(obj, f)
            logger.info(f"Saved model to {path}")
            print(f"[+] Saved {os.path.basename(path)}")
        
        # Save metadata
        metadata_path = os.path.join(ML_MODEL_DIR, "metadata.json")
        metadata = {
            "file_classifier": {
                "accuracy": file_report['accuracy'],
                "precision": file_report['weighted avg']['precision'],
                "recall": file_report['weighted avg']['recall'],
                "f1_score": file_report['weighted avg']['f1-score'],
                "training_date": pd.Timestamp.now().isoformat()
            },
            "behavior_classifier": {
                "accuracy": behavior_report['accuracy'],
                "precision": behavior_report['weighted avg']['precision'],
                "recall": behavior_report['weighted avg']['recall'],
                "f1_score": behavior_report['weighted avg']['f1-score'],
                "training_date": pd.Timestamp.now().isoformat()
            }
        }
        
        with open(metadata_path, "w") as f:
            json.dump(metadata, f, indent=2)
            logger.info(f"Saved metadata to {metadata_path}")
            print("[+] Saved metadata.json")
            
        return True
        
    except Exception as e:
        logger.error(f"Error saving models: {str(e)}")
        print(f"[-] Failed to save models: {str(e)}")
        raise

def verify_saved_models():
    """Verify all expected model files exist"""
    required_files = [
        "file_classifier.pkl",
        "behavior_model.pkl", 
        "vectorizer.pkl",
        "metadata.json"
    ]
    
    print("\n[+] Verifying saved models...")
    all_exist = True
    
    for filename in required_files:
        path = os.path.join(ML_MODEL_DIR, filename)
        if os.path.exists(path):
            print(f"  ✓ {filename} exists ({os.path.getsize(path)} bytes)")
        else:
            print(f"  ✗ {filename} missing!")
            all_exist = False
            
    return all_exist

def main():
    """Main training function with enhanced error handling"""
    try:
        print(f"[*] Starting ML model training process...")
        print(f"    Models will be saved to: {os.path.abspath(ML_MODEL_DIR)}")
        logger.info("Starting ML model training process")
        
        # ===== File Classifier Training =====
        print("\n[1/3] Training file classifier...")
        df = generate_synthetic_data()
        X = df.drop('label', axis=1)
        y = df['label']
        
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE
        )
        
        file_model = train_file_classifier(X_train, y_train)
        file_report = evaluate_model(file_model, X_test, y_test, "File Classifier")
        
        # ===== Behavior Classifier Training =====
        print("\n[2/3] Training behavior classifier...")
        behavior_data = generate_behavior_data()
        behavior_texts = [x[0] for x in behavior_data]
        behavior_labels = [x[1] for x in behavior_data]
        
        X_train_text, X_test_text, y_train_text, y_test_text = train_test_split(
            behavior_texts, behavior_labels, 
            test_size=TEST_SIZE, random_state=RANDOM_STATE
        )
        
        behavior_model, vectorizer = train_behavior_classifier(X_train_text, y_train_text)
        behavior_report = evaluate_model(
            behavior_model, 
            vectorizer.transform(X_test_text), 
            y_test_text,
            "Behavior Classifier"
        )
        
        # ===== Save Models =====
        print("\n[3/3] Saving models...")
        save_models(file_model, behavior_model, vectorizer, file_report, behavior_report)
        
        # Verification
        if verify_saved_models():
            print("\n[+] Model training completed successfully!")
            logger.info("Model training completed successfully")
        else:
            print("\n[-] Some model files are missing!")
            logger.error("Some model files failed to save")
        
    except Exception as e:
        logger.error(f"Training failed: {str(e)}")
        print(f"\n[-] Error during training: {str(e)}")
        raise

if __name__ == "__main__":
    main()