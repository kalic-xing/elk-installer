#!/bin/bash

################################################################################
# Elastic Agent Installer Script
#
# This script installs the Elastic Agent on a Windows machine via SMB and SSH.
#
# Usage:
#   sudo ./install-agent.sh -i <Target IP> -u <username> -p <password> -o <operating system>
#
# Options:
#   -i : IP address of the target machine
#   -u : Username for Windows machine
#   -p : Password for Windows machine
#   -o : Operating System type ('win' for Windows, 'lin' for Linux)
################################################################################

# ANSI color codes for log levels
COLOR_RESET="\033[0m"
COLOR_INFO="\033[0;32m"    # Green for INFO
COLOR_WARN="\033[0;33m"    # Yellow for WARNING
COLOR_ERROR="\033[0;31m"   # Red for ERROR

# Variables
target_ip=""
username=""
password=""
operating_system=""
token_file="/opt/elk-installer/tokens/enrollment_tokens.txt"
elastic_zip="/opt/elk-installer/elastic-agent-8.14.3-windows-x86_64.zip"
commands_file="/opt/elk-installer/commands"

# Logging functions
log() {
    local level="$1"
    local color="$2"
    shift 2
    echo -e "[${color}${level}${COLOR_RESET}] $(date '+%Y-%m-%d %H:%M:%S') - $*"
}

info() {
    log "INFO" "${COLOR_INFO}" "$@"
}

warn() {
    log "WARNING" "${COLOR_WARN}" "$@"
}

error() {
    log "ERROR" "${COLOR_ERROR}" "$@" >&2
}

die() {
    error "$@"
    exit 1
}

# Display usage information
usage() {
    echo "Usage: $0 -i <Windows IP> -u <username> -p <password> -o <operating system>"
    echo "  -i : IP address of the Windows machine"
    echo "  -u : Username for Windows machine"
    echo "  -p : Password for Windows machine"
    echo "  -o : Operating System type ('win' for Windows, 'lin' for Linux)"
    exit 1
}

# Parse command-line options and validate required arguments
parse_args() {
    while getopts ":i:u:p:o:" opt; do
        case $opt in
            i) target_ip="$OPTARG" ;;
            u) username="$OPTARG" ;;
            p) password="$OPTARG" ;;
            o) operating_system="$OPTARG" ;;
            \?) error "Invalid option: -$OPTARG"; usage ;;
            :) error "Option -$OPTARG requires an argument."; usage ;;
        esac
    done

    # Validate required inputs immediately after parsing
    if [ -z "$target_ip" ] || [ -z "$operating_system" ] || [ -z "$username" ] || [ -z "$password" ]; then
        error "Missing required inputs."
        usage
    fi
}


# Retrieve VPN IP (tun0 IP)
get_tun0_ip() {
    tun0_ip=$(/usr/share/kali-themes/xfce4-panel-genmon-vpnip.sh | awk -F '<txt>' '{print $2}' | awk -F '</txt>' '{print $1}')
    if [ -z "$tun0_ip" ]; then
        warn "Could not determine tun0 IP. Ensure VPN is connected."
    fi
}

# Define the function for Windows setup
install_on_windows() {
    # Check if the Elastic Agent zip file exists, download if missing
    if [ ! -f "$elastic_zip" ]; then
        info "Downloading Elastic Agent..."
        curl -sL https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-8.14.3-windows-x86_64.zip -o "$elastic_zip" || \
            die "Failed to download Elastic Agent"
    fi

    # Create the commands file if it doesn't exist
    if [ ! -f "$commands_file" ]; then
        cat << EOF > "$commands_file"
use C$
cd Windows\\Temp
put $elastic_zip
EOF
    fi

    # Upload the Elastic Agent zip file using impacket-smbclient
    info "Uploading the Elastic Agent zip file to $target_ip..."
    output=$(impacket-smbclient "$username:$password@$target_ip" -inputfile "$commands_file" 2>&1)
    if echo "$output" | grep -iq "error"; then
        error "File upload failed: $(echo "$output" | tail -n1)"
        exit 1
    fi

    # Install the Fleet Agent on the target Windows machine
    info "Installing the Elastic Agent on the Windows machine..."
    nxc_output=$(nxc smb "$target_ip" -u "$username" -p "$password" -X "Add-Content -Path C:\\Windows\\System32\\Drivers\\etc\\hosts -Value '$tun0_ip fleet01'; \
        if (\$?) { Expand-Archive C:\\Windows\\Temp\\elastic-agent-8.14.3-windows-x86_64.zip -DestinationPath C:\\Windows\\Temp -Force; \
        if (\$?) { C:\\Windows\\Temp\\elastic-agent-8.14.3-windows-x86_64\\elastic-agent.exe install --url=https://fleet01:8220 --enrollment-token='$token' -inf; \
        C:\Sysmon\Sysmon.exe -c C:\Sysmon\sysmonconfig-export.xml }}" --verbose 2>&1)

    # Check if installation was successful
    if echo "$nxc_output" | grep -iq "successfully"; then
        info "Elastic Agent installation successful!"
    else
        error "Installation failed: $(echo "$nxc_output" | tail -n2)"
        exit 1
    fi
}

# Define the function for Linux setup
install_on_linux() {
    info "Setting up Filebeat on Linux..."

    # Filebeat download link and target location
    local filebeat_url="https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-8.14.3-amd64.deb"
    local filebeat_deb="/opt/elk-installer/filebeat-8.14.3-amd64.deb"

    # Step 1: Download Filebeat .deb package if it doesn't already exist
    if [ ! -f "$filebeat_deb" ]; then
        info "Downloading Filebeat .deb package..."
        curl -sL "$filebeat_url" -o "$filebeat_deb" || die "Failed to download Filebeat .deb package"
    else
        info "Filebeat .deb package already exists at $filebeat_deb. Skipping download."
    fi

    # Step 2: Upload the Filebeat .deb package to the target Linux machine using SCP with sshpass
    info "Uploading Filebeat .deb package to $target_ip..."
    sshpass -p "$password" scp -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no "$filebeat_deb" "$username@$target_ip:/tmp/" >/dev/null || die "Failed to upload Filebeat to target Linux machine"

    # Step 3: Connect to the target machine to install, configure, and run Filebeat
    sshpass -p "$password" ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no "$username@$target_ip" bash -s <<EOF
        # Install the Filebeat .deb package silently
        echo "$password" | sudo -S dpkg -i /tmp/$(basename "$filebeat_deb") >/dev/null 2>&1 || { echo "Failed to install Filebeat"; exit 1; }

        # Replace the filebeat.yml content with the custom configuration
        echo "$password" | sudo -S bash -c 'cat <<YML > /etc/filebeat/filebeat.yml
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /var/log/*.log
      - /var/log/apache2/*.log  # Capture Apache logs

filebeat.config.modules:
  path: ${path.config}/modules.d/*.yml
  reload.enabled: true
  
setup.dashboards.enabled: true

setup.kibana:
  host: "$tun0_ip:5601"  # Kibana URL

output.elasticsearch:
  hosts: ["$tun0_ip:9200"]  # Elasticsearch output
  username: "elastic"
  password: "lablab"
YML'

        # Step 4: Enable and start Filebeat as a background service
        echo "$password" | sudo -S systemctl start filebeat >/dev/null 2>&1
EOF

    info "Filebeat setup on Linux completed successfully."
}

# Main function to control the script flow
main() {
    parse_args "$@"
    get_tun0_ip

    # Check if the token file exists
    if [ ! -f "$token_file" ]; then
        die "Token file not found at $token_file"
    fi

    # Select the appropriate token and function based on the OS
    case "$operating_system" in
        win)
            token=$(grep "Windows Policy" "$token_file" | cut -d ':' -f2)
            install_on_windows
            ;;
        lin)
            token=$(grep "Linux Policy" "$token_file" | cut -d ':' -f2)
            install_on_linux
            ;;
        *)
            error "Invalid operating system option. Use 'win' for Windows or 'lin' for Linux."
            usage
            ;;
    esac
}

# Run the main function
main "$@"
