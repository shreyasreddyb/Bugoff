# Custom Anti-Virus System

This repository provides a powerful, machine learning-augmented, memory-scanning, and sandbox-enabled Anti-Virus CLI tool. It integrates real-time monitoring, anomaly detection, ML-based threat classification, YARA-based file scanning, and memory scanning to deliver a robust malware detection and analysis solution.

## Features
**1. Real-Time File Monitoring:**

Watches critical directories for file creation and modification events using inotify.

Automatically scans new/modified files against malware database and YARA rules.

**2. Machine Learning-Based Malware Detection:**

Uses a Random Forest model to classify files as benign or malicious based on features like file size, entropy, and printable ratio.

Model can be updated and retrained separately to improve detection capabilities.

**3. Sandbox Analysis:**

Executes files in a controlled environment to observe suspicious behaviors.

Monitors process creation, file system changes, and network activity.

Generates a detailed JSON report for each file analyzed.

**4. Memory Scanning:**

Scans system memory for fileless malware, using signature matching and anomaly detection.

Detects hidden threats that evade traditional disk-based scanners.

**5. Threat Feed Integration:**

Updates local malware database with real malicious URLs from external threat intelligence feeds like URLhaus.

**6. YARA Signature Scanning:**

Uses custom YARA rules to detect malware signatures in files.

Flexible and extendable for any threat hunting use case.

**7. Anomaly Detection:**

Detects file system, process, and network anomalies.

Helps uncover stealthy malware or suspicious activities.

**8. Audit Logging:**

All critical events are logged (file detections, sandbox reports, memory scan results, etc.) to a log file for later review.

## Technologies Used
- **Python Libraries**:
  - `argparse` - Command-line argument parsing.
  - `requests` - Fetching threat intelligence feeds.
  - `yara-python` - Signature-based malware detection.
  - `psutil` - Process and system monitoring.
  - `pyinotify` - Real-time filesystem event monitoring.
  - `scapy` - Network monitoring.
  - `sklearn` - Machine Learning (Random Forest classification).
  - `pandas`, `numpy` - Data processing for ML models.
  - `pickle` - Model persistence.
  - `hashlib` - SHA-256 file hashing.
  - `subprocess`, `tempfile` - Sandbox execution management.
  - `tqdm` - Progress bars.

- **Tools/Concepts**:
  - YARA Rule Engine
  - URLhaus Threat Feed Integration
  - Sandbox Behavioral Analysis
  - Machine Learning Classification
  - Memory Malware Detection

## Prerequisites
1. Install Python (>= 3.8).
2. Install MongoDB (optional for memory scanner module if expanded).
3. Install required libraries:

   ```bash
   pip install yara-python psutil pyinotify scapy scikit-learn pandas numpy tqdm requests
4. Ensure yara is installed on your system:

   ```bash
    sudo apt install yara

## Setup
Clone this repository:

       git clone https://github.com/<your-username>/<repository-name>.git
        cd <repository-name>
Create necessary folders if not already present:

          mkdir -p /sandbox/reports
          mkdir -p /home/kali/BugOff/ml_models/
          
(Optional) Add pre-trained machine learning models into ml_models/ directory.

Update or add custom YARA rules in malware_rules.yar.

## Usage
Commands:

Update Malware Database:


    python main.py --update
Scan a Specific Directory:


    python main.py --scan /path/to/directory
Full System Scan:


    python main.py --full-scan
Real-Time Directory Monitoring:


    python main.py --monitor /path/to/watch
Anomaly Scan:


    python main.py --anomaly-scan
Machine Learning Scan of a Single File:


    python main.py --ml-scan /path/to/file
Sandbox Analysis:


    python main.py --sandbox /path/to/file
Memory Scan:


    python main.py --memory-scan
## Security Notes
Always validate downloaded threat intelligence feeds before trusting them.

For best protection, regularly update YARA rules and retrain machine learning models.

Restrict access to your Anti-Virus tool's execution to prevent misuse.

Sandbox analysis is performed locally; ensure sandboxed files are isolated properly.

Security Highlights
Memory Threat Detection: Scans for fileless malware living only in memory.

Sandbox Execution: Behavioral analysis to detect evasive threats.

YARA Scanning: Flexible, custom detection rules.

ML Classification: Predicts unknown threats based on trained features.

Audit Logs: Complete tracking and visibility into all activities.

## Acknowledgments
YARA Documentation

Scikit-Learn Machine Learning Library

URLhaus Threat Intelligence Feed

psutil and pyinotify Python Libraries

Open-source Cybersecurity Tools Community
