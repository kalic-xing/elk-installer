#!/bin/bash

#===============================================================================
# ELK Stack Agent Installer - Combined Windows/Linux Deployment
#
# Description: Automated deployment of Elastic Agent to Windows and Linux targets
# Version: 3.1 - Reduced Output
#
# Usage: ./install_agent.sh -arch <Windows|Linux> -username <user> -password <pass> -target <ip>
# Prerequisites: 
#   - Docker with Elasticsearch running
#   - Valid enrollment tokens in /opt/tokens/enrollment_tokens.txt
#   - Network connectivity to target systems
#   - For Windows: impacket-smbclient, netexec (nxc)
#   - For Linux: sshpass, ssh, scp
#===============================================================================

set -euo pipefail

#===============================================================================
# CONFIGURATION
#===============================================================================

# Script metadata
readonly SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Default configuration
readonly AGENT_DIR="/opt/elk-installer/agent-downloads"
readonly SCRIPTS_DIR="/opt/elk-installer/scripts"
readonly TOKENS_FILE="/opt/elk-installer/tokens/enrollment_tokens.txt"

# Command line arguments
TARGET_ARCH=""
USERNAME=""
PASSWORD=""
TARGET_IP=""
VERBOSE=false

# Runtime variables
ELASTICAGENT_VERSION=""
TUN0_IP=""
LINUX_TOKEN=""
WINDOWS_TOKEN=""

#===============================================================================
# LOGGING FUNCTIONS
#===============================================================================

get_timestamp() {
    date '+%Y-%m-%d %H:%M:%S'
}

log() {
    local level="$1"
    shift
    echo "[$(get_timestamp)] [$level] $*" >&2
}

log_info() {
    log "INFO" "$@"
}

log_error() {
    log "ERROR" "$@"
}

log_success() {
    log "SUCCESS" "$@"
}

log_debug() {
    [[ "$VERBOSE" == "true" ]] && log "DEBUG" "$@"
}

#===============================================================================
# ERROR HANDLING
#===============================================================================

handle_error() {
    local exit_code=$?
    local line_number=$1
    
    log_error "Script failed at line $line_number with exit code $exit_code"
    log_error "Command: ${BASH_COMMAND}"
    exit "$exit_code"
}

trap 'handle_error $LINENO' ERR

#===============================================================================
# UTILITY FUNCTIONS
#===============================================================================

show_usage() {
    cat << EOF
Usage: $SCRIPT_NAME [OPTIONS]

Deploy Elastic Agent to Windows or Linux targets via remote execution.

Required Arguments:
  -arch <Windows|Linux>    Target architecture/OS
  -username <user>         Username for remote authentication
  -password <pass>         Password for remote authentication  
  -target <ip>             Target machine IP address

Optional Arguments:
  -tun0 <ip>              Specify TUN0 IP address (auto-detected if not provided)
  -v, --verbose           Enable verbose/debug logging
  -h, --help              Show this help message

Examples:
  # Deploy to Windows target
  $SCRIPT_NAME -arch Windows -username administrator -password 'P@ssw0rd!' -target 192.168.1.100

  # Deploy to Linux target  
  $SCRIPT_NAME -arch Linux -username root -password 'password123' -target 192.168.1.101

  # With verbose logging
  $SCRIPT_NAME -arch Linux -username ubuntu -password 'mypass' -target 10.0.0.50 -v

  # With custom TUN0 IP
  $SCRIPT_NAME -arch Linux -username ubuntu -password 'mypass' -target 10.0.0.50 -tun0 192.168.1.10
Prerequisites:
  - Elasticsearch running in Docker
  - Enrollment tokens in $TOKENS_FILE
  - Network connectivity to target
  - For Windows: impacket-smbclient, netexec (nxc)
  - For Linux: sshpass, ssh, scp

EOF
}

# Parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -arch)
                TARGET_ARCH="$2"
                shift 2
                ;;
            -username)
                USERNAME="$2"
                shift 2
                ;;
            -password)
                PASSWORD="$2"
                shift 2
                ;;
            -target)
                TARGET_IP="$2"
                shift 2
                ;;
            -tun0)
                TUN0_IP="$2"
                shift 2
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            *)
                log_error "Unknown argument: $1"
                show_usage
                exit 1
                ;;
        esac
    done
}

#===============================================================================
# VALIDATION FUNCTIONS
#===============================================================================

validate_arguments() {
    log_debug "Validating command line arguments..."
    
    local validation_errors=0
    
    if [[ -z "$TARGET_ARCH" ]]; then
        log_error "Architecture not specified. Use -arch Windows or -arch Linux"
        validation_errors=$((validation_errors + 1))
    elif [[ ! "$TARGET_ARCH" =~ ^(Windows|Linux)$ ]]; then
        log_error "Invalid architecture: $TARGET_ARCH (must be Windows or Linux)"
        validation_errors=$((validation_errors + 1))
    fi
    
    if [[ -z "$USERNAME" ]]; then
        log_error "Username not provided. Use -username argument"
        validation_errors=$((validation_errors + 1))
    fi
    
    if [[ -z "$PASSWORD" ]]; then
        log_error "Password not provided. Use -password argument"
        validation_errors=$((validation_errors + 1))
    fi
    
    if [[ -z "$TARGET_IP" ]]; then
        log_error "Target IP not provided. Use -target argument"
        validation_errors=$((validation_errors + 1))
    elif ! [[ "$TARGET_IP" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        log_error "Invalid IP address format: $TARGET_IP"
        validation_errors=$((validation_errors + 1))
    fi
    
    if [[ $validation_errors -gt 0 ]]; then
        log_error "Argument validation failed with $validation_errors error(s)"
        show_usage
        return 1
    fi
    
    log_debug "Arguments validated successfully"
    return 0
}

validate_prerequisites() {
    log_debug "Validating system prerequisites..."
    
    # Check required commands based on target architecture
    local required_commands=("curl" "docker")
    
    if [[ "$TARGET_ARCH" == "Windows" ]]; then
        required_commands+=("impacket-smbclient" "nxc")
    else
        required_commands+=("sshpass" "ssh" "scp")
    fi
    
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            log_error "Required command not found: $cmd"
            log_error "Install it with: apt update && apt install -y $cmd"
            return 1
        fi
        log_debug "Found required command: $cmd"
    done
    
    # Check if tokens file exists
    if [[ ! -f "$TOKENS_FILE" ]]; then
        log_error "Enrollment tokens file not found: $TOKENS_FILE"
        log_error "Please ensure the tokens file exists with format:"
        log_error "Linux Policy:token_here"
        log_error "Windows Policy:token_here"
        return 1
    fi
    
    # Check if scripts directory exists
    if [[ ! -d "$SCRIPTS_DIR" ]]; then
        log_error "Scripts directory not found: $SCRIPTS_DIR"
        log_error "Please ensure install_agent.sh and install_agent.ps1 exist in $SCRIPTS_DIR"
        return 1
    fi
    
    log_debug "Prerequisites validated successfully"
    return 0
}

#===============================================================================
# DISCOVERY FUNCTIONS
#===============================================================================

get_elastic_agent_version() {
    log_debug "Discovering Elasticsearch version from Docker..."
    
    ELASTICAGENT_VERSION=$(docker ps --filter "name=elastic-agent" --format "{{.Image}}" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    
    if [[ -z "$ELASTICAGENT_VERSION" ]]; then
        log_error "Could not determine Elastic Agent version"
        log_error "Ensure Elastic Agent is running in Docker with 'elastic-agent' in the container name"
        return 1
    fi
    
    log_debug "Detected Elastic Agent version: $ELASTICAGENT_VERSION"
    return 0
}

get_tun0_ip() {
    # If TUN0_IP was provided via command line argument, validate and use it
    if [[ -n "$TUN0_IP" ]]; then
        log_debug "Using provided TUN0 IP: $TUN0_IP"

        # Validate IP format
        if ! [[ "$TUN0_IP" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
            log_error "Invalid TUN0 IP address format: $TUN0_IP"
            return 1
        fi
        return 0
    fi

    log_debug "Auto-detecting TUN0 IP address..."

    # Try the specific script first
    if [[ -f "/usr/share/kali-themes/xfce4-panel-genmon-vpnip.sh" ]]; then
        TUN0_IP=$(/usr/share/kali-themes/xfce4-panel-genmon-vpnip.sh 2>/dev/null | awk -F '<txt>' '{print $2}' | awk -F '</txt>' '{print $1}' 2>/dev/null || echo "")
    fi

    # Fallback: extract from ip command
    if [[ -z "$TUN0_IP" ]]; then
        TUN0_IP=$(ip addr show tun0 2>/dev/null | grep -oP 'inet \K[\d.]+' | head -1 || echo "")
    fi

    # Final fallback: extract from ifconfig
    if [[ -z "$TUN0_IP" ]] && command -v ifconfig >/dev/null 2>&1; then
        TUN0_IP=$(ifconfig tun0 2>/dev/null | grep -oP 'inet \K[\d.]+' | head -1 || echo "")
    fi

    if [[ -z "$TUN0_IP" ]]; then
        log_error "Could not determine TUN0 IP address"
        log_error "Ensure VPN connection is active and tun0 interface exists, or provide IP with -tun0 argument"
        return 1
    fi

    log_debug "Auto-detected TUN0 IP: $TUN0_IP"
    return 0
}

extract_enrollment_tokens() {
    log_debug "Extracting enrollment tokens..."
    
    if [[ ! -r "$TOKENS_FILE" ]]; then
        log_error "Cannot read tokens file: $TOKENS_FILE"
        return 1
    fi
    
    # Extract Linux token
    LINUX_TOKEN=$(grep "^Linux Policy:" "$TOKENS_FILE" | cut -d':' -f2- | tr -d ' ' || echo "")
    
    # Extract Windows token  
    WINDOWS_TOKEN=$(grep "^Windows Policy:" "$TOKENS_FILE" | cut -d':' -f2- | tr -d ' ' || echo "")
    
    if [[ -z "$LINUX_TOKEN" ]]; then
        log_error "Linux enrollment token not found in $TOKENS_FILE"
        return 1
    fi
    
    if [[ -z "$WINDOWS_TOKEN" ]]; then
        log_error "Windows enrollment token not found in $TOKENS_FILE"
        return 1
    fi
    
    log_debug "Enrollment tokens extracted successfully"
    log_debug "Linux token: ${LINUX_TOKEN:0:20}..."
    log_debug "Windows token: ${WINDOWS_TOKEN:0:20}..."
    return 0
}

#===============================================================================
# DOWNLOAD FUNCTIONS
#===============================================================================

ensure_agent_directory() {
    log_debug "Ensuring agent downloads directory exists..."
    
    if [[ ! -d "$AGENT_DIR" ]]; then
        log_debug "Creating agent directory: $AGENT_DIR"
        if ! sudo mkdir -p "$AGENT_DIR" 2>/dev/null; then
            log_error "Failed to create agent directory: $AGENT_DIR"
            return 1
        fi
    fi
    
    log_debug "Agent directory ready: $AGENT_DIR"
    return 0
}

download_windows_components() {
    log_info "Downloading Windows components..."
    
    local agent_file="elastic-agent-${ELASTICAGENT_VERSION}-windows-x86_64.zip"
    local sysmon_config="sysmonconfig-with-filedelete.xml"
    local sysmon_zip="Sysmon.zip"
    
    # Download Elastic Agent for Windows if not exists
    if [[ ! -f "$AGENT_DIR/$agent_file" ]]; then
        log_debug "Downloading Windows Elastic Agent..."
        if ! curl -sL "https://artifacts.elastic.co/downloads/beats/elastic-agent/$agent_file" -o "$AGENT_DIR/$agent_file" 2>/dev/null; then
            log_error "Failed to download Windows Elastic Agent"
            return 1
        fi
        log_success "Downloaded: $agent_file"
    else
        log_debug "Windows Elastic Agent already exists: $agent_file"
    fi
    
    # Download Sysmon configuration if not exists
    if [[ ! -f "$AGENT_DIR/$sysmon_config" ]]; then
        log_debug "Downloading Sysmon configuration..."
        if ! curl -sL "https://raw.githubusercontent.com/olafhartong/sysmon-modular/refs/heads/master/sysmonconfig-with-filedelete.xml" -o "$AGENT_DIR/$sysmon_config" 2>/dev/null; then
            log_error "Failed to download Sysmon configuration"
            return 1
        fi
        log_success "Downloaded: $sysmon_config"
    else
        log_debug "Sysmon configuration already exists: $sysmon_config"
    fi
    
    # Download Sysmon if not exists
    if [[ ! -f "$AGENT_DIR/$sysmon_zip" ]]; then
        log_debug "Downloading Sysmon..."
        if ! curl -sL "https://download.sysinternals.com/files/Sysmon.zip" -o "$AGENT_DIR/$sysmon_zip" 2>/dev/null; then
            log_error "Failed to download Sysmon"
            return 1
        fi
        log_success "Downloaded: $sysmon_zip"
    else
        log_debug "Sysmon already exists: $sysmon_zip"
    fi
    
    log_success "All Windows components ready"
    return 0
}

download_linux_components() {
    log_info "Downloading Linux components..."
    
    local agent_file="elastic-agent-${ELASTICAGENT_VERSION}-amd64.deb"
    
    # Download Elastic Agent for Linux if not exists
    if [[ ! -f "$AGENT_DIR/$agent_file" ]]; then
        log_debug "Downloading Linux Elastic Agent..."
        if ! curl -sL "https://artifacts.elastic.co/downloads/beats/elastic-agent/$agent_file" -o "$AGENT_DIR/$agent_file" 2>/dev/null; then
            log_error "Failed to download Linux Elastic Agent"
            return 1
        fi
        log_success "Downloaded: $agent_file"
    else
        log_debug "Linux Elastic Agent already exists: $agent_file"
    fi
    
    log_success "All Linux components ready"
    return 0
}

#===============================================================================
# DEPLOYMENT FUNCTIONS
#===============================================================================

deploy_windows_agent() {
    log_info "Deploying Elastic Agent to Windows target: $TARGET_IP..."
    
    local agent_file="elastic-agent-${ELASTICAGENT_VERSION}-windows-x86_64.zip"
    local sysmon_config="sysmonconfig-with-filedelete.xml"
    local sysmon_zip="Sysmon.zip"
    local install_script="setup_agent.ps1"
    
    # Create upload commands file
    local upload_commands="/tmp/smb_upload_commands_$$.txt"
    cat > "$upload_commands" << EOF
use C$
cd Windows\\Temp
put $SCRIPTS_DIR/$install_script
put $AGENT_DIR/$sysmon_config
put $AGENT_DIR/$sysmon_zip
put $AGENT_DIR/$agent_file
EOF
    
    log_debug "Uploading files via SMB..."
    log_debug "Upload commands file: $upload_commands"
    
    # Upload files using impacket-smbclient (suppress all output)
    if ! impacket-smbclient "$USERNAME:$PASSWORD@$TARGET_IP" -inputfile "$upload_commands" >/dev/null 2>&1; then
        log_error "Failed to upload files via SMB"
        rm -f "$upload_commands"
        return 1
    fi
    
    rm -f "$upload_commands"
    log_success "Files uploaded successfully"
    
    # Execute installation via netexec
    log_info "Executing Windows installation..."
    local ps_command="Import-Module C:\\Windows\\Temp\\$install_script; Install-ElasticAgentAndSysmon -tun0_ip '$TUN0_IP' -files '$sysmon_config,$agent_file,$sysmon_zip' -enrollment_token '$WINDOWS_TOKEN'"
    
    log_debug "PowerShell command: $ps_command"
    
    # Capture netexec output and check for success
    local nxc_output
    if nxc_output=$(nxc smb "$TARGET_IP" -u "$USERNAME" -p "$PASSWORD" -X "$ps_command" 2>&1); then
        # Check if installation was successful by looking for success indicator
        if echo "$nxc_output" | grep -q "Elastic Agent has been successfully installed"; then
            log_success "Windows Elastic Agent installation successful"
        elif echo "$nxc_output" | grep -q "Installation completed successfully"; then
            log_success "Windows Elastic Agent installation successful"
        else
            log_error "Windows installation may have failed - success message not found"
            if [[ "$VERBOSE" == "true" ]]; then
                echo "$nxc_output" >&2
            fi
            return 1
        fi
    else
        log_error "Failed to execute Windows installation"
        if [[ "$VERBOSE" == "true" ]]; then
            echo "$nxc_output" >&2
        fi
        return 1
    fi
    
    log_success "Windows Elastic Agent deployment completed"
    return 0
}

deploy_linux_agent() {
    log_info "Deploying Elastic Agent to Linux target: $TARGET_IP..."
    
    local agent_file="elastic-agent-${LINUX_AGENT_VERSION}-amd64.deb"
    local install_script="setup_agent.sh"
    
    # Upload script and agent package
    log_debug "Uploading files via SCP..."
    if ! sshpass -p "$PASSWORD" scp -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o IdentitiesOnly=yes "$SCRIPTS_DIR/$install_script" "$AGENT_DIR/$agent_file" "$USERNAME@$TARGET_IP:/tmp/" >/dev/null 2>&1; then
        log_error "Failed to upload files via SCP"
        log_error "Check SSH connectivity and credentials"
        return 1
    fi
    
    log_success "Files uploaded successfully"
    
    # Execute installation via SSH
    log_info "Executing Linux installation..."
    local ssh_command="echo '$PASSWORD' | sudo -S bash /tmp/$install_script --package '$agent_file' --token '$LINUX_TOKEN' --ip '$TUN0_IP' --port 8000"
    
    log_debug "SSH command: $ssh_command"
    
    # Capture SSH output and check for success
    local ssh_output
    if ssh_output=$(sshpass -p "$PASSWORD" ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o IdentitiesOnly=yes -t "$USERNAME@$TARGET_IP" "$ssh_command" 2>&1); then
        # Check if installation was successful by looking for success indicator
        if echo "$ssh_output" | grep -q "Elastic Agent has been successfully installed"; then
            log_success "Linux Elastic Agent installation successful"
        elif echo "$ssh_output" | grep -q "Installation completed successfully"; then
            log_success "Linux Elastic Agent installation successful"
        else
            log_error "Linux installation may have failed - success message not found"
            if [[ "$VERBOSE" == "true" ]]; then
                echo "$ssh_output" >&2
            fi
            return 1
        fi
    else
        log_error "Failed to execute Linux installation"
        if [[ "$VERBOSE" == "true" ]]; then
            echo "$ssh_output" >&2
        fi
        return 1
    fi
    
    log_success "Linux Elastic Agent deployment completed"
    return 0
}

#===============================================================================
# MAIN EXECUTION
#===============================================================================

main() {
    log_info "Starting ELK Agent Installer..."
    
    # Phase 1: Discovery and Validation
    validate_arguments || exit 1
    validate_prerequisites || exit 1
    ELASTICAGENT_VERSION || exit 1
    get_tun0_ip || exit 1
    extract_enrollment_tokens || exit 1
    
    # Phase 2: Download Components
    ensure_agent_directory || exit 1
    
    if [[ "$TARGET_ARCH" == "Windows" ]]; then
        download_windows_components || exit 1
    else
        download_linux_components || exit 1
    fi
    
    # Phase 3: Deploy Agent
   
    if [[ "$TARGET_ARCH" == "Windows" ]]; then
        deploy_windows_agent || exit 1
    else
        deploy_linux_agent || exit 1
    fi
    
    log_success "ELK Agent deployment completed successfully!"
    log_info "Check your Fleet management interface to verify agent enrollment"
}

#===============================================================================
# SCRIPT ENTRY POINT
#===============================================================================

# Parse arguments first
parse_arguments "$@"

# Handle the case where no arguments are provided
if [[ $# -eq 0 ]]; then
    show_usage
    exit 1
fi

# Run main installation
main