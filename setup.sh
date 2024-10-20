#!/bin/bash

set -e  # Exit immediately if a command exits with a non-zero status
set -u  # Treat unset variables as an error and exit immediately
set -o pipefail  # Exit if any command in a pipeline fails

# Minimum required RAM in MB (3.8GB = 3890MB)
MIN_RAM_MB=3890

# Enable ERR trapping in functions and subshells
set -o errtrace

# Temporary file for error output
error_log=$(mktemp)

# Trap for errors, capturing the line, the command, and the error output
trap 'last_command=$BASH_COMMAND; error_code=$?; echo "Error occurred at line $LINENO: $last_command"; echo "Error message: $(cat $error_log)"; rm -f $error_log; exit $error_code' ERR

# Function to check total RAM
check_total_ram() {
    if ! command -v free &> /dev/null; then
        echo "[ERROR] 'free' command not found. Please install it."
        exit 1
    fi

    total_ram=$(free -m | grep "Mem:" | awk '{print $2}')

    if (( total_ram < MIN_RAM_MB )); then
        echo "[ERROR] The machine does not have enough RAM. At least ${MIN_RAM_MB}MB is required."
        exit 1
    fi
}

# Call the RAM check function
check_total_ram 2>> $error_log

# Ensure the script is run as root
if (( $EUID != 0 )); then
    echo "Please run as using sudo"
    exit 1
fi

# Variables
elk_path="/opt/elk-installer"
git_repo="https://github.com/kalic-xing/elk-installer.git"
docker_repo="https://download.docker.com/linux/debian"

declare -A env_vars
env_vars=(
    ["ELASTIC_PASSWORD"]="lablab"
    ["KIBANA_PASSWORD"]="1234.Abc"
    ["STACK_VERSION"]="8.14.1"
)

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Echo status for each step
echo_step() {
    echo "[INFO] $1"
}

install_docker() {
    echo_step "Docker is not installed. Installing Docker..."
    
    mkdir -p /etc/apt/keyrings

    echo_step "Setting up Docker repository..." 
    echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.gpg] $docker_repo bookworm stable" | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
    curl -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg 2>> $error_log

    echo_step "Updating package list and installing Docker..."
    apt-get update -y >/dev/null 2>&1 && apt-get install -y docker-ce docker-ce-cli containerd.io >/dev/null 2>&1

    echo_step "Configuring Docker to start on boot..."
    systemctl enable docker --now 2>> $error_log

    echo_step "Adding user 'kali' to the Docker group..."
    usermod -aG docker kali 2>> $error_log
}

clone_repo() {
    if [ ! -d "$elk_path" ]; then
        echo_step "Cloning the ELK installer repository..." 
        git clone "$git_repo" "$elk_path" 2>> $error_log
    else
        echo_step "$elk_path already exists. Skipping clone."
    fi
}

(command_exists docker || install_docker) &
clone_repo &

wait

cd "$elk_path"

echo_step "Updating .env file with environment variables..."
for key in "${!env_vars[@]}"; do
    sed -i "s/^$key=.*/$key=${env_vars[$key]}/" ./.env 2>> $error_log
done

echo_step "Pulling the Docker images..."
docker compose pull 2>> $error_log

echo_step "Starting Docker services for Elasticsearch, Kibana, and token initialization..."
docker compose up -d elasticsearch kibana setup 2>> $error_log

echo_step "Waiting for setup to complete..."
timeout=600  
start=$(date +%s)

while [[ $(($(date +%s) - start)) -lt $timeout ]]; do
    STATUS=$(docker inspect -f '{{.State.Status}}' setup 2>> $error_log)
    
    if [[ "$STATUS" == "exited" ]]; then
        echo_step "Setup completed. Starting Fleet Agent..."
        chmod +x ./scripts/token.sh 2>> $error_log
        ./scripts/token.sh 2>> $error_log >/dev/null
        docker compose up -d elastic-agent 2>> $error_log
        break
    fi

    sleep 5  
done

if [[ $(($(date +%s) - start)) -ge $timeout ]]; then
    echo "[ERROR] Timeout reached. Setup did not complete within 10 minutes."
    exit 1
fi

check_and_add_aliases() {
    local alias_file="/home/kali/.aliases"
    local compose_file_path="/opt/elk-installer/docker-compose.yml"  

    local aliases=(
    "alias elk-start='docker compose -f $compose_file_path start elasticsearch kibana elastic-agent'"
    "alias elk-stop='docker compose -f $compose_file_path stop'"
    "alias elk-reset='(cd /opt/elk-installer && docker compose down -v && docker compose up -d elasticsearch kibana setup && echo Waiting for setup to complete... && while [ \"\$(docker inspect -f '\''{{.State.Status}}'\'' setup)\" != "exited" ]; do sleep 1; done && sudo ./scripts/token.sh && docker compose up -d elastic-agent)'"
    )

    if [ ! -f "$alias_file" ]; then
        touch "$alias_file" 2>> $error_log
    fi

    for alias in "${aliases[@]}"; do
        if ! grep -qxF "$alias" "$alias_file"; then
            echo "$alias" >> "$alias_file" 2>> $error_log
        fi
    done
}

check_and_add_aliases

echo "[INFO] ELK setup complete!"
echo ""
echo "You can now manage your ELK instance using the following commands:"
echo "  elk-start  : Starts the ELK services"
echo "  elk-stop   : Stops the ELK services"
echo "  elk-reset  : Resets the ELK services"
echo ""
echo "Access the Elastic SIEM at: http://localhost:5601"
echo ""
