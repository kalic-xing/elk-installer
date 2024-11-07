#!/bin/bash

# Variables
password=
filebeat_deb=

# Function to execute commands with sudo
sudo_cmd() {
    echo "$password" | sudo -S "$@"
}

# Function to handle errors
handle_error() {
    echo "Error: $1"
    exit 1
}

# Main installation steps
main() {
    # Install Filebeat
    sudo_cmd dpkg -i "$filebeat_deb" >/dev/null 2>&1 || handle_error "Failed to install Filebeat"

    # Configure Filebeat
    sudo_cmd bash -c "cat /tmp/filebeat.yml > /etc/filebeat/filebeat.yml" || handle_error "Failed to copy configuration file"
    
    # Enable modules
    # for module in system apache; do
    #     sudo_cmd filebeat modules enable "$module" >/dev/null 2>&1 || handle_error "Failed to enable $module module"
    # done

    # Setup pipelines
    # sudo_cmd filebeat setup --pipelines >/dev/null 2>&1 || handle_error "Failed to setup pipelines"

    # Start service
    sudo_cmd systemctl start filebeat >/dev/null 2>&1 || handle_error "Failed to start Filebeat service"

# Check if required variables are set
if [ -z "$password" ] || [ -z "$filebeat_deb" ]; then
    handle_error "Password or Filebeat package path not set"
fi

# Run main function
main