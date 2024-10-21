#!/bin/bash

# Initialize variables
windows_ip=""
username=""
password=""
operating_system=""

# Define the file where tokens are stored
token_file="/opt/elk-installer/tokens/enrollment_tokens.txt" 

# Define the path to the Elastic Agent zip file and commands file
elastic_zip="/opt/elk-installer/elastic-agent-8.14.3-windows-x86_64.zip"
commands_file="/opt/elk-installer/commands"

# Function to display usage information
usage() {
    echo "Usage: $0 -i <Windows IP> -u <username> -p <password> -o <operating system>"
    echo "  -i : IP address of the Windows machine"
    echo "  -u : Username for Windows machine"
    echo "  -p : Password for Windows machine"
    echo "  -o : Operarting System type"
    exit 1
}

# Parse command-line options
while getopts ":i:u:p:o:" opt; do
    case $opt in
        i) windows_ip="$OPTARG" ;;
        u) username="$OPTARG" ;;
        p) password="$OPTARG" ;;
        o) operating_system="$OPTARG" ;;
        \?) echo "Invalid option: -$OPTARG" >&2; usage ;;
        :) echo "Option -$OPTARG requires an argument." >&2; usage ;;
    esac
done


# Get VPN IP (tun0 IP)
tun0_ip=$(/usr/share/kali-themes/xfce4-panel-genmon-vpnip.sh | awk -F '<txt>' '{print $2}' | awk -F '</txt>' '{print $1}')

# Ensure variables are set
if [ -z "$windows_ip" ] || [ -z "$operating_system" ] || [ -z "$tun0_ip" ] || [ -z "$username" ] || [ -z "$password" ]; then
    echo "Error: Please check your inputs."
    usage
    exit 1
fi

# Echo status for each step
echo_step() {
    echo "[INFO] $1"
}

# Check if the token file exists
if [ ! -f "$token_file" ]; then
    echo "Error: Token file not found at $token_file"
    exit 1
fi

# Based on the OS, fetch the relevant token
case "$operating_system" in
    win)
        # Extract the Windows Policy token
        token=$(grep "Windows Policy" "$token_file" | cut -d ':' -f2)
        ;;
    lin)
        # Extract the Linux Policy token
        token=$(grep "Linux Policy" "$token_file" | cut -d ':' -f2)
        ;;
    *)
        echo "Invalid operating system option. Use 'win' for Windows or 'lin' for Linux."
        usage
        ;;
esac

# Check if the Elastic Agent zip file exists before downloading
if [ ! -f "$elastic_zip" ]; then
    echo_step "Downloading Elastic Agent..."
    curl -sL https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-8.14.3-windows-x86_64.zip -o "$elastic_zip"
fi

# Check if the commands file exists, if not create it
if [ ! -f "$commands_file" ]; then
    echo_step "Creating commands file..."
    cat << EOF > "$commands_file"
use C$
cd Windows\\Temp
put $elastic_zip
EOF
fi

# Upload the Elastic Agent zip file using impacket-smbclient
echo_step "Uploading the elastic agent..."
output=$(impacket-smbclient $username:$password@$windows_ip -inputfile "$commands_file" 2>&1)

# Check if the output contains the word "error"
if echo "$output" | grep -iq "error"; then
    # If the output contains "error", print the last line of the output
    echo "\n$output" | tail -n1
fi

# Install the Fleet Agent on the target Windows machine using nxc and capture the output
echo_step "Installing the elastic agent..."
nxc_output=$(nxc smb $windows_ip -u $username -p $password -X "Add-Content -Path C:\\Windows\\System32\\Drivers\\etc\\hosts -Value '$tun0_ip fleet01 elasticsearch'; \
    if (\$?) { Expand-Archive C:\\Windows\\Temp\\elastic-agent-8.14.3-windows-x86_64.zip -DestinationPath C:\\Windows\\Temp -Force; \
    if (\$?) { C:\\Windows\\Temp\\elastic-agent-8.14.3-windows-x86_64\\elastic-agent.exe install --url=https://fleet01:8220 --enrollment-token=$token -inf }}" --verbose)

# Check if the output contains the success message
if echo "$nxc_output" | grep -iq "successfully"; then
    echo_step "Elastic Agent installation successful!"
else
    echo "\n$nxc_output" | tail -n2
fi