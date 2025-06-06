#!/usr/bin/env python3
import os
import io
import csv
import re
import json
import time
import yara
import mmap
import psutil
import pickle
import logging
import hashlib
import tempfile
import subprocess
import requests
import argparse
import pandas as pd
import numpy as np
from datetime import datetime
from tqdm import tqdm
from scapy.all import sniff, IP
import pyinotify
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from memory_scanner import MemoryScanner

# ===== CONFIGURATION =====
MALWARE_DB_FILE = "malware_db.txt"
YARA_RULES_FILE = "malware_rules.yar"
LOG_FILE = "av.log"
THREAT_FEED_URL = "https://urlhaus.abuse.ch/downloads/csv_online/"
SCAN_EXCLUSIONS = ["/proc", "/sys", "/dev", "/run"]  # Directories to exclude
SUSPICIOUS_EXTENSIONS = [".exe", ".dll", ".bat", ".sh", ".py", ".js"]
SUSPICIOUS_DIRECTORIES = ["/tmp", "/var/tmp", "/dev/shm"]
MALICIOUS_IPS = ["1.2.3.4", "5.6.7.8"]  # Replace with real threat intel
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB
SANDBOX_REPORT_DIR = "/sandbox/reports"
SANDBOX_TIMEOUT = 60  # 60 seconds sandbox execution time
ML_MODEL_DIR = "/home/kali/BugOff/ml_models/"  # Where models are stored
ML_FEATURES = ['size', 'entropy', 'printable_ratio', 'is_pe']  # Features to extract

# ===== LOGGING SETUP =====
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# ===== DATABASE FUNCTIONS =====
def load_malware_db():
    """Load malware hashes from database file"""
    try:
        if os.path.exists(MALWARE_DB_FILE):
            with open(MALWARE_DB_FILE, "r") as f:
                db = set(line.strip() for line in f if line.strip())
            print(f"[+] Successfully loaded {len(db)} malware signatures")
            return db
        print("[-] Malware database not found. Use --update to create it.")
        return set()
    except Exception as e:
        logger.error(f"Error loading malware DB: {str(e)}")
        print(f"[!] Error loading malware database: {str(e)}")
        return set()

def load_yara_rules():
    """Load YARA rules with better error handling"""
    try:
        if not os.path.exists(YARA_RULES_FILE):
            print(f"[-] YARA rules file not found at {YARA_RULES_FILE}")
            return None
            
        # Test compile first
        try:
            test_rules = yara.compile(filepath=YARA_RULES_FILE)
        except yara.SyntaxError as e:
            print(f"[!] YARA syntax error: {str(e)}")
            print("[!] Please check your YARA rules file")
            return None
            
        print(f"[+] Successfully loaded YARA rules from {YARA_RULES_FILE}")
        return test_rules
        
    except yara.Error as e:
        logger.error(f"YARA rules error: {str(e)}")
        print(f"[!] Error loading YARA rules: {str(e)}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error loading YARA rules: {str(e)}")
        print(f"[!] Unexpected error: {str(e)}")
        return None

def update_malware_db():
    """Update malware database from URLhaus CSV feed"""
    try:
        print("[*] Starting malware database update...")
        logger.info("Starting malware database update")
        
        # Fetch the CSV data
        response = requests.get(THREAT_FEED_URL, timeout=30)
        if response.status_code != 200:
            logger.error(f"Failed to fetch threat feed: HTTP {response.status_code}")
            print(f"[-] Database update failed: HTTP {response.status_code}")
            return False

        # Process CSV lines (skip comments and empty lines)
        csv_lines = [
            line.strip() 
            for line in response.text.splitlines() 
            if line.strip() and not line.startswith('#')
        ]

        if not csv_lines:
            print("[-] No data found in the threat feed!")
            return False

        # Extract header (first line) and data rows
        header = csv_lines[0].strip().split(',')
        data_rows = csv_lines[1:]

        # Parse CSV rows manually (since csv.DictReader fails with commented headers)
        urls = set()
        for row in data_rows:
            try:
                # Split CSV row into columns
                row_data = row.split(',')
                if len(row_data) < 3:  # Ensure 'url' column exists
                    continue
                
                # Extract URL (3rd column in URLhaus CSV)
                url = row_data[2].strip('"')  # Remove quotes if present
                if url:
                    urls.add(url)
                    logger.debug(f"Added malicious URL: {url}")
            except Exception as e:
                logger.warning(f"Error parsing row: {row} - {str(e)}")

        # Save URLs to the database file
        with open(MALWARE_DB_FILE, "w") as f:
            f.write("# Malicious URLs from URLhaus\n")
            f.write("\n".join(sorted(urls)))

        print(f"[+] Success! Updated malware DB with {len(urls)} malicious URLs")
        logger.info(f"Updated malware DB with {len(urls)} URLs")
        return True

    except Exception as e:
        logger.error(f"Error updating malware DB: {str(e)}")
        print(f"[!] Database update error: {str(e)}")
        return False

# ===== SCANNING FUNCTIONS =====
def calculate_hash(file_path):
    """Calculate file hash with error handling"""
    try:
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        return sha256.hexdigest()
    except (IOError, OSError) as e:
        logger.debug(f"Could not hash {file_path}: {str(e)}")
        return None

def scan_file(file_path, malware_db, yara_rules):
    """Scan individual file for threats"""
    try:
        # Skip directories and special files
        if not os.path.isfile(file_path):
            return False
            
        # Skip large files
        if os.path.getsize(file_path) > MAX_FILE_SIZE:
            logger.debug(f"Skipping large file: {file_path}")
            return False
            
        filename = os.path.basename(file_path)
        for url in malware_db:
            url_filename = os.path.basename(url)
            if filename == url_filename:
                logger.warning(f"Malware detected: {file_path} (Matched URL: {url})")
                print(f"[!] Malware detected: {file_path}")
                print(f"    - Threat detected by URL pattern match: {url}")
                return True
                
        # YARA rules check
        if yara_rules:
            try:
                matches = yara_rules.match(file_path)
                if matches:
                    logger.warning(f"YARA match: {file_path} (Rule: {matches})")
                    print(f"[!] YARA rule match: {file_path}")
                    print(f"    - Matched rules: {', '.join(match.rule for match in matches)}")
                    return True
            except yara.Error as e:
                logger.debug(f"YARA error on {file_path}: {str(e)}")
                
        return False
    except Exception as e:
        logger.error(f"Scan error on {file_path}: {str(e)}")
        print(f"[!] Error scanning {file_path}: {str(e)}")
        return False

def directory_scan(path, malware_db, yara_rules):
    """Scan a specific directory"""
    if not os.path.isdir(path):
        logger.error(f"Invalid directory: {path}")
        print(f"[-] Error: {path} is not a valid directory")
        return
        
    print(f"[*] Scanning directory: {path}")
    files_scanned = 0
    threats_found = 0
    
    try:
        for root, _, files in os.walk(path):
            # Skip excluded directories
            if any(root.startswith(excl) for excl in SCAN_EXCLUSIONS):
                continue
                
            for file in files:
                file_path = os.path.join(root, file)
                files_scanned += 1
                if files_scanned % 100 == 0:
                    print(f"[*] Progress: {files_scanned} files scanned...")
                
                if scan_file(file_path, malware_db, yara_rules):
                    threats_found += 1
                    
        print(f"[+] Scan complete: {files_scanned} files scanned, {threats_found} threats detected")
        logger.info(f"Directory scan completed on {path}: {files_scanned} files, {threats_found} threats")
    except Exception as e:
        logger.error(f"Scan error: {str(e)}")
        print(f"[!] Scan error: {str(e)}")

# ===== ANOMALY DETECTION =====
def detect_file_anomalies(file_path):
    """Check for suspicious file characteristics"""
    try:
        anomalies = []
        
        # Check extensions
        if any(file_path.lower().endswith(ext) for ext in SUSPICIOUS_EXTENSIONS):
            logger.warning(f"Suspicious extension: {file_path}")
            anomalies.append("suspicious extension")
            
        # Check locations
        if any(file_path.startswith(dir) for dir in SUSPICIOUS_DIRECTORIES):
            logger.warning(f"Suspicious location: {file_path}")
            anomalies.append("suspicious location")
            
        if anomalies:
            print(f"[!] Anomaly detected: {file_path}")
            print(f"    - Reasons: {', '.join(anomalies)}")
            return True
            
        return False
    except Exception as e:
        logger.error(f"Anomaly check error: {str(e)}")
        return False

def detect_process_anomalies():
    """Check for suspicious processes"""
    anomalies_found = 0
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
        try:
            process_anomalies = []
            
            # Check suspicious locations
            if proc.info['exe'] and any(proc.info['exe'].startswith(dir) for dir in SUSPICIOUS_DIRECTORIES):
                logger.warning(f"Suspicious process: {proc.info['name']} (PID: {proc.info['pid']})")
                process_anomalies.append("running from suspicious location")
                
            # Check suspicious command lines
            if proc.info['cmdline'] and any("malware" in cmd.lower() for cmd in proc.info['cmdline']):
                logger.warning(f"Suspicious command line: {proc.info['cmdline']}")
                process_anomalies.append("suspicious command line parameters")
                
            if process_anomalies:
                print(f"[!] Suspicious process: {proc.info['name']} (PID: {proc.info['pid']})")
                print(f"    - Reasons: {', '.join(process_anomalies)}")
                anomalies_found += 1
                
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
            
    return anomalies_found

def detect_network_anomalies():
    """Check for suspicious network activity"""
    try:
        anomalies_found = 0
        for conn in psutil.net_connections():
            if conn.status == psutil.CONN_ESTABLISHED and hasattr(conn.raddr, 'ip'):
                if conn.raddr.ip in MALICIOUS_IPS:
                    logger.warning(f"Suspicious connection to {conn.raddr.ip}")
                    print(f"[!] Suspicious connection detected:")
                    print(f"    - Local:  {conn.laddr.ip}:{conn.laddr.port}")
                    print(f"    - Remote: {conn.raddr.ip}:{conn.raddr.port} (KNOWN MALICIOUS)")
                    if conn.pid:
                        try:
                            process = psutil.Process(conn.pid)
                            print(f"    - Process: {process.name()} (PID: {conn.pid})")
                        except psutil.NoSuchProcess:
                            print(f"    - Process: Unknown (PID: {conn.pid})")
                    anomalies_found += 1
        return anomalies_found
    except Exception as e:
        logger.error(f"Network check error: {str(e)}")
        print(f"[!] Network check error: {str(e)}")
        return 0

def anomaly_scan():
    """Perform comprehensive anomaly detection"""
    print("[*] Starting anomaly scan...")
    
    file_anomalies = 0
    total_files_checked = 0
    
    # File system anomalies
    print("[*] Scanning for file system anomalies...")
    for root, _, files in os.walk("/"):
        if any(root.startswith(excl) for excl in SCAN_EXCLUSIONS):
            continue
            
        for file in files:
            total_files_checked += 1
            file_path = os.path.join(root, file)
            if detect_file_anomalies(file_path):
                file_anomalies += 1
                
            if total_files_checked % 1000 == 0:
                print(f"[*] Checked {total_files_checked} files...")
    
    # Process anomalies
    print("[*] Scanning for process anomalies...")
    process_anomalies = detect_process_anomalies()
    
    # Network anomalies
    print("[*] Scanning for network anomalies...")
    network_anomalies = detect_network_anomalies()
    
    # Report results
    print("\n[+] Anomaly scan completed")
    print(f"    - Files checked: {total_files_checked}")
    print(f"    - File anomalies: {file_anomalies}")
    print(f"    - Process anomalies: {process_anomalies}")
    print(f"    - Network anomalies: {network_anomalies}")
    print(f"    - Total anomalies: {file_anomalies + process_anomalies + network_anomalies}")
    
    logger.info(f"Anomaly scan completed: {file_anomalies} file, {process_anomalies} process, {network_anomalies} network anomalies")

# ===== REAL-TIME MONITORING =====
class FileEventHandler(pyinotify.ProcessEvent):
    """Handler for real-time file system events"""
    def __init__(self, malware_db, yara_rules):
        self.malware_db = malware_db
        self.yara_rules = yara_rules
        self.events_processed = 0
        self.threats_detected = 0

    def process_IN_CREATE(self, event):
        self.process_file_event(event, "created")

    def process_IN_MODIFY(self, event):
        self.process_file_event(event, "modified")

    def process_file_event(self, event, action):
        file_path = event.pathname
        self.events_processed += 1
        print(f"[*] File {action}: {file_path}")
        if scan_file(file_path, self.malware_db, self.yara_rules):
            self.threats_detected += 1
            print(f"[!] Threat detected in {action} file: {file_path}")
        
        # Periodically report statistics
        if self.events_processed % 10 == 0:
            print(f"[*] Monitoring status: {self.events_processed} events processed, {self.threats_detected} threats detected")


class MLClassifier:
    def __init__(self):
        self.file_classifier = None
        self.behavior_model = None
        self.vectorizer = None
        self.load_models()
        
    def load_models(self):
        """Load pre-trained ML models with better error handling"""
        try:
            # Create ML model directory if it doesn't exist
            os.makedirs(ML_MODEL_DIR, exist_ok=True)
            
            # Load file classifier
            classifier_path = os.path.join(ML_MODEL_DIR, "file_classifier.pkl")
            if os.path.exists(classifier_path):
                with open(classifier_path, "rb") as f:
                    self.file_classifier = pickle.load(f)
                print("[+] File classifier loaded successfully")
            else:
                print(f"[-] Model file not found: {classifier_path}")
                
            # TODO: Add loading for behavior_model and vectorizer
            # Currently these remain None as per original code
            
        except Exception as e:
            print(f"[-] Critical error loading models: {str(e)}")
            logger.error(f"Model loading failed: {str(e)}")
    
    def model_status(self):
        """Check if models are loaded and ready"""
        # Modified to only check file_classifier since others aren't used
        return self.file_classifier is not None

    def extract_features(self, file_path):
        """Extract features ensuring they match model requirements"""
        features = {}
        try:
            if not os.path.exists(file_path):
                print(f"[-] File not found: {file_path}")
                return None
                
            # Required features in EXACT order the model expects
            features['size'] = os.path.getsize(file_path)
            
            # Entropy calculation
            with open(file_path, "rb") as f:
                data = f.read(4096)
                if not data:
                    return None
                    
                byte_counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
                byte_probs = byte_counts / len(data)
                features['entropy'] = -np.sum(byte_probs * np.log2(byte_probs, where=byte_probs>0))
                
                # PE header check
                f.seek(0)
                features['is_pe'] = f.read(2) == b'MZ'
                
            # Add printable ratio if needed by model
            with open(file_path, "rb") as f:
                data = f.read(4096)
                printable = sum(32 <= byte <= 126 for byte in data)
                features['printable_ratio'] = printable / len(data) if data else 0
                
            # Ensure ALL expected features are present
            for feature in ML_FEATURES:
                if feature not in features:
                    print(f"[-] Missing required feature: {feature}")
                    return None
                    
            # Return features in consistent order
            return pd.DataFrame([features])[ML_FEATURES]
            
        except Exception as e:
            print(f"Feature extraction failed: {str(e)}")
            return None
            

    def classify_file(self, file_path):
        """Classify a file using ML model with better error handling"""
        if not self.file_classifier:
            print("[-] No classifier model loaded")
            return None
            
        try:
            features = self.extract_features(file_path)
            if features is None:
                return None
                
            # Ensure features match what the model expects
            if not all(col in features for col in ML_FEATURES):
                print("[-] Extracted features don't match model requirements")
                return None
                
            prediction = self.file_classifier.predict(features)
            proba = self.file_classifier.predict_proba(features)
            
            # Return (prediction, probability) where probability is for the positive class
            return prediction[0], proba[0][1]
            
        except Exception as e:
            print(f"[-] Classification failed: {str(e)}")
            logger.error(f"Classification error on {file_path}: {str(e)}")
            return None

# This should be a standalone function, not a class method
def ml_scan(file_path, ml_classifier):
    """Perform ML-based scan on a file"""
    try:
        if not os.path.isfile(file_path):
            print(f"[-] Invalid file path: {file_path}")
            return False
            
        print(f"[*] Performing ML scan on: {file_path}")
        
        result = ml_classifier.classify_file(file_path)
        if result is None:
            print("[-] ML scan could not complete")
            return False
            
        prediction, probability = result
        if prediction == 1:  # Assuming 1 is malicious
            print(f"[!] MALICIOUS DETECTED - Probability: {probability:.2%}")
            return True
        else:
            print(f"[+] File appears benign - Confidence: {1-probability:.2%}")
            return False
            
    except Exception as e:
        logger.error(f"ML scan error on {file_path}: {str(e)}")
        print(f"[!] ML scan failed: {str(e)}")
        return False

def start_monitoring(path_to_watch):
    """Start real-time file monitoring"""
    if not os.path.isdir(path_to_watch):
        print(f"[-] Error: {path_to_watch} is not a valid directory")
        return
        
    print(f"[*] Starting real-time monitoring on: {path_to_watch}")
    
    malware_db = load_malware_db()
    yara_rules = load_yara_rules()
    
    # Initialize watcher
    watch_manager = pyinotify.WatchManager()
    event_handler = FileEventHandler(malware_db, yara_rules)
    notifier = pyinotify.Notifier(watch_manager, event_handler)
    
    try:
        # Add watch
        mask = pyinotify.IN_CREATE | pyinotify.IN_MODIFY
        watch_descriptor = watch_manager.add_watch(path_to_watch, mask, rec=True)
        
        if watch_descriptor[path_to_watch] > 0:
            print(f"[+] Successfully established watch on {path_to_watch}")
        else:
            print(f"[-] Failed to establish watch on {path_to_watch}")
            return
            
        # Report monitoring started
        print("[+] Real-time monitoring active")
        print("    - Press Ctrl+C to stop monitoring")
        
        # Start monitoring loop
        network_check_counter = 0
        process_check_counter = 0
        
        while True:
            notifier.process_events()
            if notifier.check_events():
                notifier.read_events()
            
            # Also check for process/network anomalies periodically
            network_check_counter += 1
            process_check_counter += 1
            
            if process_check_counter >= 60:  # Check processes every minute
                process_check_counter = 0
                anomalies = detect_process_anomalies()
                if anomalies > 0:
                    print(f"[!] Detected {anomalies} suspicious processes during periodic check")
                    
            if network_check_counter >= 300:  # Check network every 5 minutes
                network_check_counter = 0
                anomalies = detect_network_anomalies()
                if anomalies > 0:
                    print(f"[!] Detected {anomalies} suspicious network connections during periodic check")
            
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[+] Monitoring stopped by user")
        print(f"    - Events processed: {event_handler.events_processed}")
        print(f"    - Threats detected: {event_handler.threats_detected}")
    except Exception as e:
        logger.error(f"Monitoring error: {str(e)}")
        print(f"[!] Monitoring error: {str(e)}")

class SandboxAnalyzer:
    def __init__(self, timeout=60):
        self.timeout = timeout
        self.report_dir = SANDBOX_REPORT_DIR
        os.makedirs(self.report_dir, exist_ok=True)
        
    def analyze(self, file_path):
        """Analyze a file in sandbox environment"""
        if not os.path.isfile(file_path):
            return None
            
        report = {
            'file': file_path,
            'timestamp': datetime.now().isoformat(),
            'malicious': False,
            'suspicious_activities': [],
            'processes_created': [],
            'files_created': [],
            'network_connections': []
        }
        
        # Create temporary directory for sandbox
        with tempfile.TemporaryDirectory() as temp_dir:
            try:
                # Copy file to sandbox
                sandbox_path = os.path.join(temp_dir, os.path.basename(file_path))
                with open(file_path, 'rb') as src, open(sandbox_path, 'wb') as dst:
                    dst.write(src.read())
                
                # Make executable if not already
                os.chmod(sandbox_path, 0o755)
                
                # Start monitoring processes
                initial_processes = set(p.pid for p in psutil.process_iter())
                
                # Execute in sandbox
                start_time = time.time()
                proc = subprocess.Popen(
                    sandbox_path,
                    cwd=temp_dir,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    shell=True
                )
                
                try:
                    # Monitor while process runs
                    while proc.poll() is None and (time.time() - start_time) < self.timeout:
                        self._monitor_activities(proc.pid, report, temp_dir)
                        time.sleep(1)
                    
                    # Process finished or timeout
                    if proc.poll() is None:
                        proc.terminate()
                        report['timeout'] = True
                        report['suspicious_activities'].append("Process timeout - possible hang")
                    else:
                        report['exit_code'] = proc.returncode
                        
                    # Check for new processes
                    self._check_processes(initial_processes, report)
                    
                    # Final monitoring
                    self._monitor_activities(proc.pid, report, temp_dir)
                    
                except Exception as e:
                    report['error'] = str(e)
                    logger.error(f"Sandbox error monitoring {file_path}: {str(e)}")
                
                # Check results for malicious indicators
                self._evaluate_behavior(report)
                
            except Exception as e:
                report['error'] = str(e)
                logger.error(f"Sandbox error analyzing {file_path}: {str(e)}")
                
        # Save report
        self._save_report(report)
        return report
        
    def _monitor_activities(self, pid, report, temp_dir):
        """Monitor activities of the process"""
        try:
            process = psutil.Process(pid)
            
            # Check network connections
            for conn in process.connections():
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    network_info = {
                        'local': f"{conn.laddr.ip}:{conn.laddr.port}",
                        'remote': f"{conn.raddr.ip}:{conn.raddr.port}",
                        'status': conn.status
                    }
                    if network_info not in report['network_connections']:
                        report['network_connections'].append(network_info)
                        if conn.raddr.ip not in ['127.0.0.1']:
                            report['suspicious_activities'].append(
                                f"Established connection to {conn.raddr.ip}:{conn.raddr.port}"
                            )
            
            # Check file operations
            open_files = process.open_files()
            for f in open_files:
                if not f.path.startswith(temp_dir) and f.path not in report['files_created']:
                    report['files_created'].append(f.path)
                    report['suspicious_activities'].append(f"Accessed file: {f.path}")
                    
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
            
    def _check_processes(self, initial_processes, report):
        """Check for newly created processes"""
        current_processes = set(p.pid for p in psutil.process_iter())
        new_processes = current_processes - initial_processes
        
        for pid in new_processes:
            try:
                p = psutil.Process(pid)
                info = {
                    'pid': pid,
                    'name': p.name(),
                    'cmdline': p.cmdline(),
                    'create_time': p.create_time()
                }
                report['processes_created'].append(info)
                report['suspicious_activities'].append(f"Spawned new process: {p.name()} (PID: {pid})")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
                
    def _evaluate_behavior(self, report):
        """Evaluate behavior for malicious indicators"""
        malicious_indicators = [
            'Created hidden file',
            'Modified system directory',
            'Accessed sensitive path',
            'Established connection to',
            'Spawned new process',
            'Process timeout'
        ]
        
        suspicious_count = 0
        for activity in report['suspicious_activities']:
            if any(indicator in activity for indicator in malicious_indicators):
                suspicious_count += 1
                
        if suspicious_count >= 2:  # At least 2 suspicious activities
            report['malicious'] = True
        elif 'network_connections' in report and len(report['network_connections']) > 3:
            report['malicious'] = True
        elif 'processes_created' in report and len(report['processes_created']) > 2:
            report['malicious'] = True
            
    def _save_report(self, report):
        """Save analysis report to file"""
        try:
            filename = f"report_{os.path.basename(report['file'])}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            report_path = os.path.join(self.report_dir, filename)
            
            with open(report_path, 'w') as f:
                json.dump(report, f, indent=2)
                
            logger.info(f"Saved sandbox report: {report_path}")
        except Exception as e:
            logger.error(f"Error saving sandbox report: {str(e)}")

def sandbox_analyze(file_path):
    """Analyze a specific file in the sandbox"""
    if not os.path.isfile(file_path):
        print(f"[-] Error: {file_path} is not a valid file")
        return
        
    print(f"[*] Starting sandbox analysis of: {file_path}")
    print(f"    - Timeout: {SANDBOX_TIMEOUT} seconds")
    print("    - Monitoring for:")
    print("        * Process creation")
    print("        * File system changes")
    print("        * Network activity")
    
    sandbox = SandboxAnalyzer(timeout=SANDBOX_TIMEOUT)
    report = sandbox.analyze(file_path)
    
    if report:
        print("\n[+] Sandbox analysis completed")
        print(f"    - File: {report['file']}")
        print(f"    - Timestamp: {report['timestamp']}")
        print(f"    - Malicious: {'Yes' if report['malicious'] else 'No'}")
        
        if report['malicious']:
            print("\n[!] MALICIOUS BEHAVIOR DETECTED!")
            print("    Suspicious activities:")
            for activity in report['suspicious_activities']:
                print(f"    - {activity}")
                
        if report.get('error'):
            print(f"\n[!] Errors occurred during analysis: {report['error']}")
            
        print(f"\nReport saved to: {os.path.join(SANDBOX_REPORT_DIR, os.path.basename(report['file']))}_*.json")
    else:
        print("[-] Sandbox analysis failed")

# ===== MAIN FUNCTION =====
def main():
    parser = argparse.ArgumentParser(
        description="Custom Anti-Virus System",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "--scan",
        help="Scan a specific directory",
        metavar="DIRECTORY"
    )
    parser.add_argument(
        "--monitor",
        help="Monitor a directory in real-time",
        metavar="DIRECTORY"
    )
    parser.add_argument(
        "--update",
        help="Update malware signatures database",
        action="store_true"
    )
    parser.add_argument(
        "--full-scan",
        help="Perform full system scan",
        action="store_true"
    )
    parser.add_argument(
        "--anomaly-scan",
        help="Perform anomaly detection scan",
        action="store_true"
    )
    parser.add_argument(
        "--ml-scan",
        help="Perform ML-based scan on a file",
        metavar="FILE"
    )
    parser.add_argument(
        "--sandbox",
        help="Analyze a specific file in sandbox",
        metavar="FILE"
    )
    parser.add_argument(
        "--memory-scan",
        help="Perform memory scan for fileless malware",
        action="store_true"
    )

    args = parser.parse_args()
    
    # Print banner
    print("=" * 60)
    print("Custom Anti-Virus System")
    print("=" * 60)
    
    try:
        if args.update:
            if update_malware_db():
                print("[+] Database update completed successfully")
            else:
                print("[-] Database update failed")
                
        elif args.scan:
            print(f"[*] Initializing scan of {args.scan}")
            malware_db = load_malware_db()
            yara_rules = load_yara_rules()
            directory_scan(args.scan, malware_db, yara_rules)
            print("[+] Scan completed")
            
        elif args.monitor:
            start_monitoring(args.monitor)
            
        elif args.full_scan:
            print("[*] Starting full system scan (this may take a while)...")
            malware_db = load_malware_db()
            yara_rules = load_yara_rules()
            directory_scan("/", malware_db, yara_rules)
            print("[+] Full system scan completed")
            
        elif args.anomaly_scan:
            anomaly_scan()

        elif args.ml_scan:
            if not os.path.isfile(args.ml_scan):
                print(f"[-] Error: {args.ml_scan} is not a valid file")
            else:
                ml_classifier = MLClassifier()
                if ml_classifier.model_status():
                    if ml_scan(args.ml_scan, ml_classifier):
                        print("[!] ML scan detected potential threats")
                    else:
                        print("[+] ML scan found no threats")
                else:
                    print("[-] ML models not available. Please train models first.")
        
        elif args.sandbox:
            sandbox_analyze(args.sandbox)

        elif args.memory_scan:
            print("[*] Starting memory scan...")
            scanner = MemoryScanner()
            threats = scanner.scan()
            if threats:
                print(f"[!] Detected {len(threats)} memory threats:")
                for threat in threats:
                    print(f"    - {threat}")
            else:
                print("[+] No memory threats detected")
            
        else:
            parser.print_help()
            print("\n[*] No action specified. Use one of the options above.")
            
    except KeyboardInterrupt:
        print("\n[!] Operation interrupted by user")
    except Exception as e:
        logger.critical(f"Fatal error: {str(e)}")
        print(f"[!] Fatal error: {str(e)}")
        raise

if __name__ == "__main__":
    main()