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
installer_dir="/opt/elk-installer"
token_file="$installer_dir/tokens/enrollment_tokens.txt"


# Variables for options
install_sysmon_only=false # Default value

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
    echo "  --sysmon : Installs sysmon windows machines"
    exit 1
}

# Parse command-line options and validate required arguments
parse_args() {
    while getopts ":i:u:p:o:-:" opt; do
        case $opt in
            i) target_ip="$OPTARG" ;;
            u) username="$OPTARG" ;;
            p) password="$OPTARG" ;;
            o) operating_system="$OPTARG" ;;
            -)
                case "$OPTARG" in
                    sysmon) install_sysmon_only=true ;;  # Set sysmon flag if --sysmon is provided
                    *) error "Invalid option: --$OPTARG"; usage ;;
                esac
                ;;
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

# Reusable function to upload files to target Windows machine
upload_files() {
    local ip="$1"
    local files=("${@:2}")
    local commands_file="$installer_dir/commands_upload.txt"

    # Prepare commands file for uploading files
    : > "$commands_file"  # Clear existing commands
    echo "use C$" >> "$commands_file"
    echo "cd Windows\\Temp" >> "$commands_file"
    for file in "${files[@]}"; do
        echo "put $file" >> "$commands_file"
    done

    # Run the upload command
    info "Uploading files to $ip..."
    output=$(impacket-smbclient "$username:$password@$ip" -inputfile "$commands_file" 2>&1)
    if echo "$output" | grep -iq "error"; then
        error "File upload failed for $ip: $(echo "$output" | tail -n1)"
        return 1  # Return with error if upload fails
    fi
}

# function to execute remote commands on Windows
execute_remote_command() {
    local ip="$1"
    local command="$2"

    nxc_output=$(nxc smb "$ip" -u "$username" -p "$password" -X "$command" --verbose 2>&1)
    if echo "$nxc_output" | grep -iq "successfully"; then
        info "Command executed successfully on $ip!"
        return 0
    else
        error "Command execution failed for $ip: $(echo "$nxc_output" | tail -n2)"
        return 1
    fi
}

# Function to install the Elastic Agent and optionally Sysmon on Windows
install_on_windows() {
    # Define URLs for Sysmon and configuration
    local sysmon_zip_url="https://download.sysinternals.com/files/Sysmon.zip"
    local sysmon_config_url="https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig-with-filedelete.xml"
    local elastic_agent_url="https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-8.14.3-windows-x86_64.zip"

    # Variables for file locations
    local elastic_zip="$installer_dir/elastic-agent-8.14.3-windows-x86_64.zip"
    local sysmon_zip="$installer_dir/Sysmon.zip"
    local sysmon_config="$installer_dir/sysmonconfig.xml"

    # Download Elastic Agent zip file if it doesn't exist
    if [ ! -f "$elastic_zip" ]; then
        info "Downloading Elastic Agent..."
        curl -sL "$elastic_agent_url" -o "$elastic_zip" || die "Failed to download Elastic Agent"
    fi

    # Download Sysmon files if --sysmon is set
    if [ "$install_sysmon_only" = true ]; then
        if [ ! -f "$sysmon_zip" ]; then
            info "Downloading Sysmon..."
            curl -sL "$sysmon_zip_url" -o "$sysmon_zip" || die "Failed to download Sysmon"
        fi
        if [ ! -f "$sysmon_config" ]; then
            info "Downloading Sysmon configuration file..."
            curl -sL "$sysmon_config_url" -o "$sysmon_config" || die "Failed to download Sysmon configuration file"
        fi
    fi

    # Array to hold PIDs for both upload and installation processes
    declare -a process_pids=()

    files_to_upload=("$elastic_zip")
    [ "$install_sysmon_only" = true ] && files_to_upload+=("$sysmon_zip" "$sysmon_config")

        # Upload files
        if upload_files "$target_ip" "${files_to_upload[@]}"; then
            # Define installation command based on --sysmon option
            if [ "$install_sysmon_only" = true ]; then
                info "Installing Elastic Agent and Sysmon..."
                nxc_command="Add-Content -Path C:\\Windows\\System32\\Drivers\\etc\\hosts -Value '$tun0_ip fleet01'; \
                    if (\$?) { Expand-Archive C:\\Windows\\Temp\\elastic-agent-8.14.3-windows-x86_64.zip -DestinationPath C:\\Windows\\Temp -Force; \
                    if (\$?) { C:\\Windows\\Temp\\elastic-agent-8.14.3-windows-x86_64\\elastic-agent.exe install --url=https://fleet01:8220 --enrollment-token='$token' -inf; }; \
                    if (!(Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue)) { \
                        Expand-Archive C:\\Windows\\Temp\\Sysmon.zip -DestinationPath C:\\Sysmon -Force; \
                        C:\\Sysmon\\Sysmon64.exe -accepteula -i C:\\Windows\\Temp\\sysmonconfig.xml; }}"

            else
                info "Installing Elastic Agent ..."
                nxc_command="Add-Content -Path C:\\Windows\\System32\\Drivers\\etc\\hosts -Value '$tun0_ip fleet01'; \
                    if (\$?) { Expand-Archive C:\\Windows\\Temp\\elastic-agent-8.14.3-windows-x86_64.zip -DestinationPath C:\\Windows\\Temp -Force; \
                    if (\$?) { C:\\Windows\\Temp\\elastic-agent-8.14.3-windows-x86_64\\elastic-agent.exe install --url=https://fleet01:8220 --enrollment-token='$token' -inf; \
                    C:\Sysmon\Sysmon.exe -c C:\Sysmon\sysmonconfig-export.xml }}"
            fi

            # Execute the installation command and check the result
            execute_remote_command "$target_ip" "$nxc_command"

        else
             error "Failed to upload files to $target_ip"
        fi
}

# Define the function for Linux setup
install_on_linux() {
    # Variables for Elastic Agent
    local elastic_agent_url="https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-8.14.3-amd64.deb"
    local elastic_agent="$installer_dir/elastic-agent-8.14.3-amd64.deb"
    local install_script="$installer_dir/elastic-agent/install.sh"

    # Step 1: Download Elastic Agent .deb package if it doesn't already exist
    if [ ! -f "$elastic_agent" ]; then
        info "Downloading Elastic Agent .deb package..."
        curl -sL "$elastic_agent_url" -o "$elastic_agent" || die "Failed to download Elastic Agent .deb package"
    fi

    # Step 2: Update the install_script with dynamic values
    info "Updating install script with paths and password..."
    declare -A script_vars=(
        ["^tun0_ip=.*"]="tun0_ip=$tun0_ip"
        ["^enrollment_key=.*"]="enrollment_key=$token"
        ["^password=.*"]="password=$password"
        ["^elastic_agent=.*"]="elastic_agent=/tmp/$(basename "$elastic_agent")"
    )
    
    for key in "${!script_vars[@]}"; do
        sed -i "s|$key|${script_vars[$key]}|" "$install_script"
    done

    # Step 3: Upload the Elastic Agent .deb package and the install script to the target Linux machine using SCP
    info "Uploading Elastic Agent .deb package and install script to $target_ip..."
    sshpass -p "$password" scp -q -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no \
        "$elastic_agent" "$install_script" "$username@$target_ip:/tmp/" >/dev/null 2>&1 || \
        die "Failed to upload files to target Linux machine $target_ip"

    # Step 4: Execute the script on the remote machine to install and configure the Elastic Agent
    info "Executing the Elastic Agent install script..."
    sshpass -p "$password" ssh -q -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no \
        "$username@$target_ip" "bash /tmp/$(basename "$install_script")" 2>/dev/null || \
        die "Failed to run the installation script on the target machine $target_ip"

    info "Elastic Agent setup on Linux completed successfully."
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
