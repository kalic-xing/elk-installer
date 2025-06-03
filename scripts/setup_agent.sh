#!/bin/bash

#===============================================================================
# Elastic Agent Installation Script
#
# Description: Automated installation and enrollment of Elastic Agent
# Version: 3.0
#
# Usage: ./install.sh --package <deb_file> --token <token>
# Prerequisites: 
#   - Script must be executed as root
#   - Target system must be Debian-based
#===============================================================================

set -euo pipefail  # Exit on error, undefined variables, and pipe failures

#===============================================================================
# CONFIGURATION
#===============================================================================

# Configuration variables (set via command line arguments)
CONFIG_AGENT_DEB_PACKAGE=""
CONFIG_ENROLLMENT_TOKEN=""
CONFIG_TUN0_IP=""
CONFIG_PORT=""

# Optional configuration with defaults
CONFIG_FLEET_URL="https://fleet01:8220"
CONFIG_FLEET_HOST="fleet01"
CONFIG_LOG_LEVEL="INFO"
CONFIG_UPLOAD_DIR="/tmp"

# Script metadata
readonly SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

#===============================================================================
# LOGGING FUNCTIONS
#===============================================================================

# Dynamic timestamp function
get_timestamp() {
    date '+%Y-%m-%d %H:%M:%S'
}

# Logging function with levels
log() {
    local level="$1"
    shift
    echo "[$(get_timestamp)] [$level] $*" >&2
}

log_info() {
    [[ "$CONFIG_LOG_LEVEL" == "DEBUG" || "$CONFIG_LOG_LEVEL" == "INFO" ]] && log "INFO" "$@"
}

log_error() {
    log "ERROR" "$@"
}

log_debug() {
    [[ "$CONFIG_LOG_LEVEL" == "DEBUG" ]] && log "DEBUG" "$@"
}

# Remote-friendly status reporting
log_remote_status() {
    local phase="$1"
    local status="$2"
    local message="$3"
    
    echo "REMOTE_STATUS: [$phase] [$status] $message" >&2
    log "$status" "$message"
}

#===============================================================================
# ERROR HANDLING
#===============================================================================

# Enhanced error handler with cleanup
handle_error() {
    local exit_code=$?
    local line_number=$1
    
    log_error "Script failed at line $line_number with exit code $exit_code"
    log_error "Command: ${BASH_COMMAND}"
    log_remote_status "ERROR" "FAILED" "Installation failed at line $line_number"
    
    # Perform cleanup if needed
    cleanup_on_error
    
    exit "$exit_code"
}

# Cleanup function for error scenarios
cleanup_on_error() {
    log_info "Performing cleanup after error..."
    
    # Stop elastic-agent service if it was started
    if systemctl is-active --quiet elastic-agent 2>/dev/null; then
        log_info "Stopping elastic-agent service..."
        systemctl stop elastic-agent 2>/dev/null || true
    fi
    
    # Remove any uploaded packages
    if [[ -n "${CONFIG_UPLOAD_DIR:-}" && -n "${CONFIG_AGENT_DEB_PACKAGE:-}" ]]; then
        local package_path="${CONFIG_UPLOAD_DIR}/${CONFIG_AGENT_DEB_PACKAGE}"
        if [[ -f "$package_path" ]]; then
            log_info "Removing uploaded package: $package_path"
            rm -f "$package_path" 2>/dev/null || true
        fi
    fi
}

# Set up error trap
trap 'handle_error $LINENO' ERR

#===============================================================================
# ARGUMENT PARSING
#===============================================================================

# Parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --package)
                CONFIG_AGENT_DEB_PACKAGE="$2"
                shift 2
                ;;
            --token)
                CONFIG_ENROLLMENT_TOKEN="$2"
                shift 2
                ;;
            --ip)
                CONFIG_TUN0_IP="$2"
                shift 2
                ;;
            --port)
                CONFIG_PORT="$2"
                shift 2
                ;;
            --fleet-url)
                CONFIG_FLEET_URL="$2"
                shift 2
                ;;
            --fleet-host)
                CONFIG_FLEET_HOST="$2"
                shift 2
                ;;
            --log-level)
                CONFIG_LOG_LEVEL="$2"
                shift 2
                ;;
            --upload-dir)
                CONFIG_UPLOAD_DIR="$2"
                shift 2
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
# UTILITY FUNCTIONS
#===============================================================================

# Validate file exists and is readable
validate_file() {
    local file_path="$1"
    local file_desc="$2"
    
    if [[ ! -f "$file_path" ]]; then
        log_error "$file_desc not found: $file_path"
        return 1
    fi
    
    if [[ ! -r "$file_path" ]]; then
        log_error "$file_desc is not readable: $file_path"
        return 1
    fi
    
    log_debug "Validated $file_desc: $file_path"
    return 0
}

# Check if service exists and get its status
check_service_status() {
    local service_name="$1"
    
    if systemctl list-unit-files | grep -q "^$service_name.service"; then
        local status
        status=$(systemctl is-active "$service_name" 2>/dev/null || echo "inactive")
        log_debug "Service $service_name status: $status"
        echo "$status"
        return 0
    else
        echo "not-found"
        return 1
    fi
}

#===============================================================================
# VALIDATION FUNCTIONS
#===============================================================================

# Validate root privileges
validate_root_privileges() {
    log_info "Validating root privileges..."
    
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        log_error "Execute via SSH with sudo:"
        log_error "ssh -t user@target 'echo \"password\" | sudo -S curl http://server/install.sh -o /tmp/install.sh && sudo bash /tmp/install.sh [arguments]'"
        log_remote_status "VALIDATION" "FAILED" "Script not running as root"
        exit 1
    fi
    
    log_info "Running with root privileges - OK"
    return 0
}

# Comprehensive configuration validation
validate_configuration() {
    log_info "Validating configuration..."
    log_remote_status "VALIDATION" "IN_PROGRESS" "Validating configuration parameters"
    
    local validation_errors=0
    
    # Check required arguments
    if [[ -z "$CONFIG_AGENT_DEB_PACKAGE" ]]; then
        log_error "Elastic Agent package name not provided. Use --package argument."
        validation_errors=$((validation_errors + 1))
    fi
    
    if [[ -z "$CONFIG_ENROLLMENT_TOKEN" ]]; then
        log_error "Enrollment token not provided. Use --token argument."
        validation_errors=$((validation_errors + 1))
    fi
    
    # Validate package name format
    if [[ -n "$CONFIG_AGENT_DEB_PACKAGE" ]] && [[ ! "$CONFIG_AGENT_DEB_PACKAGE" == *.deb ]]; then
        log_error "Agent package must be a .deb file: $CONFIG_AGENT_DEB_PACKAGE"
        validation_errors=$((validation_errors + 1))
    fi
    
    # Validate log level
    if [[ ! "$CONFIG_LOG_LEVEL" =~ ^(DEBUG|INFO|ERROR)$ ]]; then
        log_error "Invalid log level: $CONFIG_LOG_LEVEL (must be DEBUG, INFO, or ERROR)"
        validation_errors=$((validation_errors + 1))
    fi
    
    if [[ $validation_errors -gt 0 ]]; then
        log_error "Configuration validation failed with $validation_errors error(s)"
        log_remote_status "VALIDATION" "FAILED" "Configuration validation failed"
        return 1
    fi
    
    log_info "Configuration validation successful"
    log_remote_status "VALIDATION" "SUCCESS" "Configuration validated"
    return 0
}

# Validate system prerequisites
validate_system() {
    log_info "Validating system prerequisites..."
    log_remote_status "VALIDATION" "IN_PROGRESS" "Validating system prerequisites"
    
    # Check if running on supported system
    if [[ ! -f /etc/debian_version ]]; then
        log_error "This script is designed for Debian-based systems"
        log_remote_status "VALIDATION" "FAILED" "Unsupported system type"
        return 1
    fi
    
    # Check required commands
    local required_commands=("dpkg" "systemctl" "curl" "file")
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            log_error "Required command not found: $cmd"
            log_remote_status "VALIDATION" "FAILED" "Missing required command: $cmd"
            return 1
        fi
    done
    
    log_info "System validation successful"
    log_remote_status "VALIDATION" "SUCCESS" "System prerequisites validated"
    return 0
}

validate_uploads() {
    local deb_package="$1"
    local upload_dir="$2"

    local local_package_path="${upload_dir}/${deb_package}"

    # Verify the uploaded file
    if [[ -f "$local_package_path" ]]; then
        local file_size
        file_size=$(stat -c%s "$local_package_path" 2>/dev/null || echo "0")
                
        if [[ "$file_size" -gt 0 ]]; then
            log_info "Upload verification successful (Size: ${file_size} bytes)"
                    
            # Basic .deb package validation
            if file "$local_package_path" | grep -q "Debian binary package"; then
                log_info "Package format validation successful"
                log_remote_status "UPLOAD" "SUCCESS" "Package upload and validated"
                echo "$local_package_path"  # Return the path
                return 0
            else
                log_error "Upload file is not a valid Debian package"
                rm -f "$local_package_path"
                return 1
            fi
        else
            log_error "Upload file is empty"
            rm -f "$local_package_path"
        fi
    else
        log_error "Upload file not found"
    fi
}

# Validate network connectivity
validate_connectivity() {
    local url="$1"
    local timeout=10
    
    log_info "Testing connectivity to $url..."
    
    if timeout "$timeout" curl -s --insecure --connect-timeout 5 "$url" >/dev/null 2>&1; then
        log_info "Connectivity test successful"
        return 0
    else
        log_error "Cannot reach $url - please check network connectivity"
        return 1
    fi
}

#===============================================================================
# INSTALLATION FUNCTIONS
#===============================================================================

# Update /etc/hosts file
update_hosts_file() {
    local ip="$1"
    local hostname="$2"
    local hosts_entry="$ip $hostname"
    
    log_info "Adding hosts entry: $hosts_entry"
    log_remote_status "HOSTS" "IN_PROGRESS" "Updating hosts file"
    
    # Check if entry already exists
    if grep -q "$hostname" /etc/hosts 2>/dev/null; then
        log_info "Host entry for $hostname already exists, skipping..."
        log_remote_status "HOSTS" "SKIPPED" "Host entry already exists"
        return 0
    fi
    
    # Add entry to hosts file
    if echo "$hosts_entry" >> /etc/hosts; then
        log_info "Successfully added hosts entry"
        log_remote_status "HOSTS" "SUCCESS" "Host entry added successfully"
        return 0
    else
        log_error "Failed to add entry to /etc/hosts"
        log_remote_status "HOSTS" "FAILED" "Failed to add host entry"
        return 1
    fi
}

# Install Elastic Agent package
install_elastic_agent() {
    local package_path="$1"
    
    log_info "Installing Elastic Agent from: $package_path"
    log_remote_status "INSTALL" "IN_PROGRESS" "Installing Elastic Agent package"
    
    # Check if already installed
    if dpkg -l | grep -q elastic-agent 2>/dev/null; then
        log_info "Elastic Agent is already installed"
        log_remote_status "INSTALL" "SKIPPED" "Elastic Agent already installed"
        return 0
    fi
    
    # Install package
    if dpkg -i "$package_path"; then
        log_info "Elastic Agent installed successfully"
        log_remote_status "INSTALL" "SUCCESS" "Package installed successfully"
        return 0
    else
        log_error "Failed to install Elastic Agent package"
        log_remote_status "INSTALL" "FAILED" "Package installation failed"
        return 1
    fi
}

# Start Elastic Agent service
start_elastic_service() {
    log_info "Starting Elastic Agent service..."
    log_remote_status "SERVICE" "IN_PROGRESS" "Starting Elastic Agent service"
    
    # Check if service is already active using direct systemctl command
    if systemctl is-active --quiet elastic-agent 2>/dev/null; then
        log_info "Elastic Agent service is already running"
        log_remote_status "SERVICE" "SKIPPED" "Service already running"
        return 0
    fi
    
    # Check if service exists before attempting to start
    if ! systemctl list-unit-files elastic-agent.service --no-legend --no-pager 2>/dev/null | grep -q "elastic-agent.service"; then
        log_error "Elastic Agent service not found in systemd"
        log_remote_status "SERVICE" "FAILED" "Service not found"
        return 1
    fi
    
    log_info "Attempting to start Elastic Agent service..."
    
    # Start the service with better error handling
    if systemctl start elastic-agent 2>/dev/null; then
        log_info "Service start command executed successfully"
        
        # Wait for service to be fully started with improved checking
        local max_wait=45  # Increased timeout
        local wait_count=0
        local check_interval=2  # Check every 2 seconds instead of 1
        
        log_info "Waiting for service to become active (timeout: ${max_wait}s)..."
        
        while [[ $wait_count -lt $max_wait ]]; do
            # Use multiple methods to check service status
            local is_active=false
            
            # Method 1: systemctl is-active
            if systemctl is-active --quiet elastic-agent 2>/dev/null; then
                is_active=true
            fi
            
            # Method 2: systemctl status with specific checks
            local status_output
            status_output=$(systemctl status elastic-agent --no-pager --lines=0 2>/dev/null || echo "")
            if echo "$status_output" | grep -q "Active: active (running)"; then
                is_active=true
            fi
            
            if [[ "$is_active" == "true" ]]; then
                log_info "Service is now active and running"
                log_remote_status "SERVICE" "SUCCESS" "Service started and active"
                
                # Additional verification: check if the process is actually running
                if pgrep -f "elastic-agent" >/dev/null 2>&1; then
                    log_info "Elastic Agent process confirmed running"
                    return 0
                else
                    log_info "Service active but process not detected yet, continuing to wait..."
                fi
            fi
            
            # Show progress every 10 seconds
            if (( wait_count % 10 == 0 )) && (( wait_count > 0 )); then
                log_info "Still waiting for service to become active... (${wait_count}/${max_wait}s)"
                # Show current status for debugging
                local current_status
                current_status=$(systemctl is-active elastic-agent 2>/dev/null || echo "unknown")
                log_debug "Current service status: $current_status"
            fi
            
            sleep $check_interval
            wait_count=$((wait_count + check_interval))
        done
        
        # Final status check with detailed information
        log_error "Service failed to become active within $max_wait seconds"
        log_error "Final service status check:"
        
        local final_status
        final_status=$(systemctl is-active elastic-agent 2>/dev/null || echo "unknown")
        log_error "  systemctl is-active: $final_status"
        
        local final_state
        final_state=$(systemctl is-enabled elastic-agent 2>/dev/null || echo "unknown")
        log_error "  systemctl is-enabled: $final_state"
        
        # Show service status for debugging
        log_error "Service status output:"
        systemctl status elastic-agent --no-pager --lines=5 2>&1 | while read -r line; do
            log_error "  $line"
        done
        
        log_remote_status "SERVICE" "FAILED" "Service failed to become active within timeout"
        return 1
    else
        local start_exit_code=$?
        log_error "Failed to start Elastic Agent service (exit code: $start_exit_code)"
        
        # Show why the start failed
        log_error "Service start failure details:"
        systemctl status elastic-agent --no-pager --lines=10 2>&1 | while read -r line; do
            log_error "  $line"
        done
        
        log_remote_status "SERVICE" "FAILED" "Failed to start service"
        return 1
    fi
}

# Enroll Elastic Agent
enroll_elastic_agent() {
    local fleet_url="$1"
    local enrollment_token="$2"
    
    log_info "Enrolling Elastic Agent with Fleet server..."
    log_debug "Fleet URL: $fleet_url"
    log_remote_status "ENROLLMENT" "IN_PROGRESS" "Enrolling with Fleet server"
    
    # Test connectivity before enrollment
    if ! validate_connectivity "$fleet_url"; then
        log_remote_status "ENROLLMENT" "FAILED" "Cannot reach Fleet server"
        return 1
    fi
    
    # Perform enrollment
    local enrollment_output
    local enrollment_cmd="elastic-agent enroll --url='$fleet_url' --enrollment-token='$enrollment_token' --insecure"
    
    log_debug "Executing enrollment command"
    enrollment_output=$(eval $enrollment_cmd 2>&1) || {
        log_error "Enrollment command failed"
        log_error "Output: $enrollment_output"
        log_remote_status "ENROLLMENT" "FAILED" "Enrollment command failed"
        return 1
    }
    
    # Verify successful enrollment
    if echo "$enrollment_output" | grep -iq "successfully"; then
        log_info "Agent enrolled successfully"
        log_debug "Enrollment output: $enrollment_output"
        log_remote_status "ENROLLMENT" "SUCCESS" "Agent enrolled successfully"
        return 0
    else
        log_error "Enrollment failed - success message not found in output"
        log_error "Output: $enrollment_output"
        log_remote_status "ENROLLMENT" "FAILED" "Enrollment verification failed"
        return 1
    fi
}

# Clean up installation files
cleanup_installation_files() {
    local package_path="$1"
    
    log_info "Cleaning up installation files..."
    log_remote_status "CLEANUP" "IN_PROGRESS" "Cleaning up installation files"
    
    # Remove agent package file
    if [[ -f "$package_path" ]]; then
        if rm "$package_path" 2>/dev/null; then
            log_info "Removed agent package file: $package_path"
            log_remote_status "CLEANUP" "SUCCESS" "Installation files cleaned up"
        else
            log_error "Failed to remove agent package file: $package_path"
            log_remote_status "CLEANUP" "WARNING" "Failed to remove some files"
        fi
    fi
}

#===============================================================================
# MAIN INSTALLATION PROCESS
#===============================================================================

# Main installation orchestrator
main() {
    log_info "Starting Elastic Agent installation process..."
    log_info "Script: $SCRIPT_NAME"
    log_info "Working directory: $SCRIPT_DIR"
    log_remote_status "MAIN" "STARTED" "Installation process initiated"
    
    # Phase 1: Validation
    log_info "=== PHASE 1: VALIDATION ==="
    validate_root_privileges || exit 1
    validate_configuration || exit 1
    validate_system || exit 1
    
    local uploaded_package_path
    uploaded_package_path=$(validate_uploads "$CONFIG_AGENT_DEB_PACKAGE" $CONFIG_UPLOAD_DIR)

    # Phase 2:
    log_info "=== PHASE 2: INSTALLATION & CLEANUP ==="
    
    update_hosts_file "$CONFIG_TUN0_IP" "$CONFIG_FLEET_HOST" || exit 1
    install_elastic_agent "$uploaded_package_path" || exit 1
    cleanup_installation_files "$uploaded_package_path" || exit 1
    start_elastic_service || exit 1
    enroll_elastic_agent "$CONFIG_FLEET_URL" "$CONFIG_ENROLLMENT_TOKEN" || exit 1
    
    log_info "Elastic Agent installation completed successfully!"
    log_info "Agent should now be visible in your Fleet management interface."
    log_remote_status "MAIN" "COMPLETED" "Installation completed successfully"
}

#===============================================================================
# SCRIPT ENTRY POINT
#===============================================================================

# Display usage information
show_usage() {
    cat << EOF
Usage: $SCRIPT_NAME [OPTIONS]

This script must be run as root. It installs the Elastic Agent,
then enrolls it with Fleet server.

Required Arguments:
  --package <file>      Name of Elastic Agent .deb package file
  --token <token>       Fleet enrollment token

Optional Arguments:
  --fleet-url <url>     Fleet server URL (default: https://fleet01:8220)
  --fleet-host <host>   Fleet hostname for /etc/hosts (default: fleet01)
  --log-level <level>   Logging level: DEBUG, INFO, ERROR (default: INFO)
  --upload-dir <dir>  Upload directory (default: /tmp)
  -h, --help           Show this help message

Examples:
  # Basic usage
  ./$SCRIPT_NAME --package "elastic-agent-8.14.3-amd64.deb" --token "enrollment_token_here" 
  # With custom Fleet server
  ./$SCRIPT_NAME --package "elastic-agent-8.14.3-amd64.deb" --token "enrollment_token_here" --fleet-url "https://fleet.example.com:8220"
  # With debug logging
  ./$SCRIPT_NAME --package "elastic-agent-8.14.3-amd64.deb" --token "enrollment_token_here" --log-level DEBUG

EOF
}

# Parse command line arguments first
parse_arguments "$@"

# Handle the case where no arguments are provided
if [[ $# -eq 0 ]]; then
    show_usage
    exit 1
fi

# Run main installation
main