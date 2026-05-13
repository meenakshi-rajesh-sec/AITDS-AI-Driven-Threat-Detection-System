#!/bin/bash
# AITDS - AI Threat Detection System
# Main execution script

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Project root directory
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$PROJECT_ROOT/src"

# Python executable
PYTHON_CMD="python3"

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                AITDS - AI Threat Detection System            ║"
    echo "║              Production-Grade SOC Intrusion Detection          ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Function to check if virtual environment exists
check_venv() {
    if [ ! -d "$PROJECT_ROOT/aitds_env" ]; then
        print_status "Creating virtual environment..."
        $PYTHON_CMD -m venv "$PROJECT_ROOT/aitds_env"
    fi
    
    # Activate virtual environment
    source "$PROJECT_ROOT/aitds_env/bin/activate"
    
    # Upgrade pip
    "$PROJECT_ROOT/aitds_env/bin/pip" install --upgrade pip
}

# Function to install dependencies
install_dependencies() {
    print_status "Installing Python dependencies..."
    
    if [ -f "$PROJECT_ROOT/requirements.txt" ]; then
        "$PROJECT_ROOT/aitds_env/bin/pip" install -r "$PROJECT_ROOT/requirements.txt"
    else
        print_error "requirements.txt not found!"
        exit 1
    fi
}

# Function to check system requirements
check_requirements() {
    print_status "Checking system requirements..."
    
    # Check Python version
    PYTHON_VERSION=$($PYTHON_CMD -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    PYTHON_MAJOR=$($PYTHON_CMD -c "import sys; print(sys.version_info.major)")
    PYTHON_MINOR=$($PYTHON_CMD -c "import sys; print(sys.version_info.minor)")
    
    if [[ $PYTHON_MAJOR -gt 3 ]] || [[ $PYTHON_MAJOR -eq 3 && $PYTHON_MINOR -ge 8 ]]; then
        print_status "Python version: $PYTHON_VERSION ✓"
    else
        print_error "Python 3.8+ required. Found: $PYTHON_VERSION"
        exit 1
    fi
    
    # Check if running as root for network capture
    if [[ $EUID -ne 0 ]]; then
        print_warning "Not running as root. Network capture may require elevated privileges."
        print_warning "Consider running with 'sudo' for full functionality."
    fi
    
    # Check for required system packages
    if ! command -v tcpdump &> /dev/null; then
        print_warning "tcpdump not found. Install with: sudo apt-get install tcpdump"
    fi
    
    if ! command -v scapy &> /dev/null; then
        print_warning "Scapy not found. Will be installed via pip."
    fi
}

# Function to train models
train_models() {
    print_status "Training ML models..."
    
    cd "$SRC_DIR"
    
    # Train supervised model
    print_status "Training supervised model (Random Forest)..."
    $PYTHON_CMD train_supervised.py
    
    # Train unsupervised model
    print_status "Training unsupervised model (Isolation Forest)..."
    $PYTHON_CMD train_unsupervised.py
    
    print_status "Model training completed!"
}

# Function to start AITDS
start_aitds() {
    print_status "Starting AITDS..."
    
    cd "$SRC_DIR"
    
    # Check if models exist
    if [ ! -f "$PROJECT_ROOT/models/supervised_rf.pkl" ] || [ ! -f "$PROJECT_ROOT/models/unsupervised_if.pkl" ]; then
        print_warning "Models not found. Training models first..."
        train_models
    fi
    
    # Start the main system
    $PYTHON_CMD run_aitds.py
}

# Function to start anomaly generator
start_anomaly_generator() {
    print_status "Starting anomaly generator..."
    print_warning "This will generate real network traffic for testing!"
    print_status "In another terminal, run: ./run.sh to start detection"
    
    cd "$PROJECT_ROOT/attacks"
    $PYTHON_CMD anomaly_generator.py
}

# Function to start specific attack generators
start_attack() {
    local attack_type="$1"
    print_status "Starting $attack_type attack generator..."
    print_warning "This will generate real network traffic for testing!"
    print_status "In another terminal, run: ./run.sh to start detection"
    
    cd "$PROJECT_ROOT/attacks"
    $PYTHON_CMD individual_generators.py "$attack_type" --duration 30
}

# Function to show help
show_help() {
    echo "AITDS - AI Threat Detection System"
    echo ""
    echo "Usage: $0 [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  start              Start AITDS system (default)"
    echo "  train              Train ML models only"
    echo "  generate           Start anomaly generator"
    echo "  dos                Generate DoS attack"
    echo "  ddos               Generate DDoS attack"
    echo "  portscan           Generate Port Scan attack"
    echo "  bruteforce         Generate Brute Force attack"
    echo "  zeroday            Generate Zero-Day anomaly"
    echo "  protocol_anomaly   Generate Protocol Zero-Day anomaly"
    echo "  volume_anomaly     Generate Volume Zero-Day anomaly"
    echo "  install            Install dependencies"
    echo "  check              Check system requirements"
    echo "  help               Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                 Start AITDS"
    echo "  $0 train           Train models"
    echo "  $0 generate        Generate attack traffic"
    echo "  $0 dos             Generate DoS attack"
    echo "  $0 zeroday        Generate Zero-Day anomaly"
    echo "  $0 protocol_anomaly Generate zero-day protocol anomaly"
    echo ""
    echo "Two-terminal usage:"
    echo "  Terminal 1: ./run.sh"
    echo "  Terminal 2: ./run.sh dos (or any attack type)"
}

# Function to create logs directory
setup_directories() {
    print_status "Creating required directories..."
    
    mkdir -p "$PROJECT_ROOT/logs"
    mkdir -p "$PROJECT_ROOT/models"
    mkdir -p "$PROJECT_ROOT/datasets/CICIDS2017"
    mkdir -p "$PROJECT_ROOT/attacks"
    
    print_status "Directories created!"
}

# Main script logic
main() {
    print_header
    
    # Setup directories
    setup_directories
    
    # Check command
    case "${1:-start}" in
        "start")
            check_requirements
            check_venv
            install_dependencies
            start_aitds
            ;;
        "train")
            check_requirements
            check_venv
            install_dependencies
            train_models
            ;;
        "generate")
            check_requirements
            check_venv
            install_dependencies
            start_anomaly_generator
            ;;
        "dos")
            check_requirements
            check_venv
            install_dependencies
            start_attack "dos"
            ;;
        "ddos")
            check_requirements
            check_venv
            install_dependencies
            start_attack "ddos"
            ;;
        "portscan")
            check_requirements
            check_venv
            install_dependencies
            start_attack "portscan"
            ;;
        "bruteforce")
            check_requirements
            check_venv
            install_dependencies
            start_attack "bruteforce"
            ;;
        "zeroday")
            check_requirements
            check_venv
            install_dependencies
            start_attack "zeroday"
            ;;
        "protocol_anomaly")
            check_requirements
            check_venv
            install_dependencies
            start_attack "zeroday"
            ;;
        "volume_anomaly")
            check_requirements
            check_venv
            install_dependencies
            start_attack "zeroday"
            ;;
        "install")
            check_requirements
            check_venv
            install_dependencies
            print_status "Dependencies installed successfully!"
            ;;
        "check")
            check_requirements
            print_status "System requirements check completed!"
            ;;
        "help"|"-h"|"--help")
            show_help
            ;;
        *)
            print_error "Unknown command: $1"
            show_help
            exit 1
            ;;
    esac
}

# Trap signals for graceful shutdown
trap 'print_status "Shutting down..."; exit 0' SIGINT SIGTERM

# Run main function
main "$@"
