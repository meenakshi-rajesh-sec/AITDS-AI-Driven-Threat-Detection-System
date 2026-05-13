#  AITDS — AI-Driven Threat Detection System

> A real-time AI-powered network threat detection and SOC monitoring platform that detects both known cyberattacks and zero-day anomalies using supervised and unsupervised machine learning techniques.

---

##  Objective

AITDS simulates a real-world Security Operations Center (SOC) environment capable of monitoring live network traffic, detecting malicious behavior, and visualizing threats in real time.

The system combines:

- **Supervised Machine Learning** for detecting known attack signatures
- **Unsupervised Machine Learning** for identifying zero-day anomalies
- **Live packet capture** and flow aggregation
- **SOC-grade detection logic** and real-time graphical dashboard monitoring

---

##  Features

| Feature | Description |
|---------|-------------|
|  Hybrid AI Detection Engine | Combines supervised and unsupervised ML models |
|  Live Packet Capture | Captures and analyzes real-time traffic via Scapy |
|  Known Attack Detection | Detects attacks using a trained Random Forest classifier |
|  Zero-Day Anomaly Detection | Identifies unknown threats using Isolation Forest |
|  SOC-Grade Detection Logic | Event-driven classification and threat validation |
|  Professional SOC Dashboard | Real-time monitoring with live metrics and alerts |
|  Attack Timeline Visualization | Graphical representation of attack trends over time |
|  Secure Authentication System | Login-based access control with hashed credentials |
|  Live Threat Statistics | Detection rates, attack counts, anomalies, and active flows |
|  Flow-Based Traffic Analysis | Extracts and analyzes network flow features |
|  Multi-threaded Monitoring | Background detection and packet processing workers |

---

##  Tools & Technologies

| Tool | Purpose |
|------|---------|
| Python 3 | Core programming language |
| Scikit-learn | Machine learning models |
| Pandas | Dataset preprocessing |
| NumPy | Numerical computations |
| Scapy | Packet capture and traffic analysis |
| Tkinter | GUI dashboard |
| Matplotlib | Threat visualization graphs |
| Random Forest | Supervised attack detection |
| Isolation Forest | Zero-day anomaly detection |
| Pickle | Model serialization |
| Kali Linux | Testing and development environment |
| Git & GitHub | Version control and project hosting |

---

##  Project Structure

```text
AITDS/
├── alerts/
│   ├── alert_manager.py
│   ├── console_alert.py
│   ├── discord_alert.py
│   ├── file_alert.py
│   ├── __init__.py
│   └── logging/
│
├── attacks/
│   ├── anomaly_generator.py
│   ├── attack_generators.py
│   ├── flow_injector.py
│   └── individual_generators.py
│
├── datasets/
│   └── CICIDS2017/
│
├── logs/
│   └── auth.log
│
├── models/
│   ├── supervised_rf.pkl
│   ├── supervised_scaler.pkl
│   ├── unsupervised_if.pkl
│   ├── unsupervised_models/
│   └── unsupervised_scaler.pkl
│
├── src/
│   ├── alerts.py
│   ├── config.py
│   ├── detector.py
│   ├── gui_dashboard.py
│   ├── gui_login.py
│   ├── live_capture.py
│   ├── run_aitds.py
│   ├── train_supervised.py
│   └── train_unsupervised.py
│
├── PROJECT_STRUCTURE.md
├── README.md
├── requirements.txt
└── run.sh
```

---

##  Setup

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/AITDS.git
cd AITDS
```

### 2. Create & Activate Virtual Environment

```bash
python3 -m venv aitds-env
source aitds-env/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the Project

```bash
sudo ./run.sh
```

>  Root privileges are required for live packet capture and traffic monitoring using Scapy.

---

##  Attack Simulation & Testing

Open a second terminal while the system is running and use these commands to simulate attacks in real time:

| Attack Type | Command |
|------------|---------|
|  DoS Attack | `sudo ./run.sh dos` |
|  DDoS Attack | `sudo ./run.sh ddos` |
|  Port Scanning | `sudo ./run.sh portscan` |
|  Brute Force | `sudo ./run.sh bruteforce` |
|  Protocol Anomaly | `sudo ./run.sh protocol_anomaly` |
|  Volume Anomaly | `sudo ./run.sh volume_anomaly` |

---

##  Machine Learning Architecture

###  Supervised Learning — Random Forest Classifier

Trained on labeled **CICIDS2017** traffic data to detect known attack patterns.

Detected attack categories:
- DDoS
- DoS
- Port Scanning
- Brute Force
- Botnet Activity
- Web Attacks
- Infiltration Attempts

###  Unsupervised Learning — Isolation Forest

Trained exclusively on **BENIGN** traffic to detect unknown or zero-day anomalies.

Detected anomaly types:
- Protocol anomalies
- Traffic volume anomalies
- Behavioral anomalies
- Abnormal packet distributions
- Asymmetric traffic flows

---

##  Extracted Network Features

| Feature | Description |
|---------|-------------|
| `flow_duration` | Duration of network flow |
| `total_fwd_packets` | Forward packet count |
| `total_bwd_packets` | Backward packet count |
| `packet_length_mean` | Average packet size |
| `packet_length_std` | Packet size deviation |
| `protocol` | Network protocol |
| `destination_port` | Destination port number |
| `flow_bytes_per_sec` | Byte transmission rate |
| `flow_packets_per_sec` | Packet transmission rate |
| `connection_count` | Active connection count |

---

##  Dashboard Components

The SOC dashboard includes:

- Real-time threat table
- Attack timeline graph
- Detection statistics panel
- Active threat counter
- Detection rate metrics
- Monitoring controls
- Engine and capture status indicators

---

##  Authentication

The system includes a secure login interface with **SHA-256 hashed** password authentication.

| Username | Password |
|----------|----------|
| `admin` | `admin123` |
| `analyst` | `analyst123` |
| `viewer` | `viewer123` |

>  Default credentials should be changed before deployment.

---

##  Dependencies

Install all dependencies with:

```bash
pip install -r requirements.txt
```

Key packages: `scikit-learn`, `pandas`, `numpy`, `scapy`, `matplotlib`, `tkinter`

---

##  Security Notes

- Packet sniffing requires root/admin privileges
- Run the system only in authorized environments
- Default credentials must be changed before deployment
- Models should be retrained periodically with updated datasets
- Large-scale deployment requires optimization for high-traffic environments

---

##  Future Improvements

- Deep learning-based threat detection
- SIEM integration
- Real-time alert notifications
- Distributed traffic monitoring
- Cloud deployment support
- Threat intelligence integration
- Database-backed event logging
- Web-based dashboard interface
- Automated incident response

---

##  Skills Demonstrated

- Practical implementation of AI-based intrusion detection systems
- Real-time packet capture using Scapy
- Flow-based traffic feature extraction
- Supervised ML model training with Random Forest
- Unsupervised anomaly detection with Isolation Forest
- Detection engineering and SOC-style event correlation
- Multi-threaded application development in Python
- GUI development using Tkinter and Matplotlib
- Authentication system implementation
- Detection statistics visualization and timeline analysis
- Dataset preprocessing and feature engineering (CICIDS2017, NSL-KDD)

---

##  License

MIT License — see [LICENSE](LICENSE) for details.
