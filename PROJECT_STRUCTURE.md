# AITDS Advanced - Clean Project Structure

## Essential Project Files (Kept)

### Core Files
- `README.md` - Project documentation
- `requirements.txt` - Python dependencies
- `run.sh` - Main execution script

### Core Directories
- `src/` - Source code (detector, GUI, etc.)
- `attacks/` - Attack generators
- `models/` - ML models
- `datasets/` - Training datasets
- `alerts/` - Alert storage
- `logs/` - System logs
- `capture/` - Network capture storage
- `aitds_env/` - Python virtual environment

## Removed Files (Cleanup)

### Test Files (Removed)
- `test_*.sh` - All test scripts (12 files removed)

### Summary Files (Removed)
- `*FIX_SUMMARY.md` - Fix documentation files
- `*FIX_FINAL.md` - Final fix summaries
- `dos_fix_summary.md` - DoS fix summary
- `FINAL_FIXES_SUMMARY.md` - Complete fixes summary

### Verification Scripts (Removed)
- `verify_*.sh` - GUI verification scripts
- `final_demo.sh` - Demo script
- `final_test.sh` - Final test script

## Final Clean Structure
```
AITDS_Advanced/
├── README.md
├── requirements.txt
├── run.sh
├── src/
│   ├── detector.py
│   ├── gui.py
│   └── ... (other source files)
├── attacks/
│   └── individual_generators.py
├── models/
│   └── ... (ML model files)
├── datasets/
│   └── ... (dataset files)
├── alerts/
├── logs/
├── capture/
└── aitds_env/
```

## Usage
```bash
# Start the detection system
./run.sh

# Generate specific attacks
./run.sh dos
./run.sh ddos
./run.sh portscan
./run.sh protocol_anomaly
./run.sh volume_anomaly
./run.sh zeroday
./run.sh bruteforce
```

The project is now clean with only essential files needed for operation.
