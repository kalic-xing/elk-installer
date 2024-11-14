#!/bin/bash

# Variables
password=
elastic_agent=
enrollment_key=
tun0_ip=

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
    # Add entry to /etc/hosts
    sudo_cmd bash -c "echo '$tun0_ip fleet01' >> /etc/hosts" || handle_error "Failed to add entry to /etc/hosts"

    # Install Elastic Agent
    sudo_cmd dpkg -i "$elastic_agent" >/dev/null 2>&1 || handle_error "Failed to install Elastic Agent"

    # Delete the Elastic Agent deb package
    rm $elastic_agent || handle_error "Failed to delete Elastic Agent deb package"

    # Start the Elastic Agent service
    sudo_cmd systemctl start elastic-agent >/dev/null 2>&1 || handle_error "Failed to start the Elastic Agent service"

    # Enroll the agent
    enrollment_output=$(sudo_cmd elastic-agent enroll --url=https://fleet01:8220 --enrollment-token="$enrollment_key" --insecure 2>&1)
    
    # Check for successful enrollment
    if echo "$enrollment_output" | grep -iqv "successfully"; then
        handle_error "Enrollment failed. Output: $enrollment_output"        
    fi

    # Self-delete the script
    rm -- "$0"
}

# Check if required variables are set
if [ -z "$password" ] || [ -z "$elastic_agent" ] || [ -z "$enrollment_key" ] || [ -z "$tun0_ip" ]; then
    handle_error "Required variables (password, elastic_agent, enrollment_key, tun0_ip) are not set"
fi

# Run main function
main
