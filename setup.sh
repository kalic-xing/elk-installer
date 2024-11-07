#!/bin/bash

################################################################################
# ELK Stack Installation Script
# 
# This script automates the installation and configuration of the ELK stack
# using Docker, ensuring that all required dependencies and configurations 
# are properly set up.
#
# Requirements:
# - Minimum 3.8GB RAM
# - Root privileges
# - Debian-based system
#
# Usage: sudo ./setup.sh
################################################################################

# Strict error handling and enhanced environment
set -euo pipefail
IFS=$'\n\t'

# Global configurations
readonly MIN_RAM_MB=3890
readonly ELK_PATH="/opt/elk-installer"
readonly GIT_REPO="https://github.com/kalic-xing/elk-installer.git"
readonly DOCKER_REPO="https://download.docker.com/linux/debian"
readonly SETUP_TIMEOUT=600  # 10 minutes
readonly ERROR_LOG=$(mktemp)
readonly DOCKER_GPG_KEY="/etc/apt/keyrings/docker.gpg"
readonly DOCKER_SOURCE_LIST="/etc/apt/sources.list.d/docker.list"

# Environment variables for ELK
declare -A ENV_VARS
ENV_VARS=(
    ["ELASTIC_PASSWORD"]="lablab"
    ["KIBANA_PASSWORD"]="1234.Abc"
    ["STACK_VERSION"]="8.14.1"
)

################################################################################
# Logging and error handling
################################################################################

# ANSI color codes for log levels
COLOR_RESET="\033[0m"
COLOR_INFO="\033[0;32m"    # Green for INFO
COLOR_WARN="\033[0;33m"    # Yellow for WARNING
COLOR_ERROR="\033[0;31m"   # Red for ERROR

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

cleanup() {
    local exit_code=$?
    rm -f "${ERROR_LOG}"
    if [ ${exit_code} -ne 0 ]; then
        error "Script failed with exit code ${exit_code}"
        if [ -f "${ERROR_LOG}" ]; then
            error "Last error: $(cat "${ERROR_LOG}")"
        fi
    fi
    exit ${exit_code}
}

################################################################################
# System checks
################################################################################

check_root() {
    if [ "$EUID" -ne 0 ]; then
        die "Please run the script with sudo or as root."
    fi
}

check_ram() {
    if ! command -v free >/dev/null 2>&1; then
        die "'free' command not found. Please install the procps package."
    fi

    local total_ram
    total_ram=$(free -m | awk '/^Mem:/{print $2}')

    if [ "${total_ram}" -lt "${MIN_RAM_MB}" ]; then
        warn "Insufficient RAM: ${total_ram}MB. For optimal SIEM performance, Consider upgrading to atleast 4GB after installation for efficient operation."
        sleep 3
    fi
}


check_dependencies() {
    local deps=("curl" "git" "gpg" "awk")
    local missing_deps=()

    for dep in "${deps[@]}"; do
        if ! command -v "${dep}" >/dev/null 2>&1; then
            missing_deps+=("${dep}")
        fi
    done

    if [ ${#missing_deps[@]} -ne 0 ]; then
        die "Missing required dependencies: ${missing_deps[*]}"
    fi
}

################################################################################
# Docker installation and configuration
################################################################################

verify_gpg_key() {
    local key_url="$1"
    local temp_key
    temp_key=$(mktemp)
    
    if ! curl -fsSL "${key_url}" -o "${temp_key}"; then
        rm -f "${temp_key}"
        return 1
    fi
    
    if ! gpg --quiet --dry-run "${temp_key}" >/dev/null 2>&1; then
        rm -f "${temp_key}"
        return 1
    fi
    
    rm -f "${temp_key}"
    return 0
}

setup_docker_repository() {
    info "Setting up Docker repository..."
    
    mkdir -p /etc/apt/keyrings

    info "Adding Docker's official GPG key..."
    curl -fsSL "${DOCKER_REPO}/gpg" | gpg --dearmor -o "${DOCKER_GPG_KEY}" 2>>"${ERROR_LOG}" || \
        die "Failed to add Docker GPG key"

    if [ ! -f "${DOCKER_SOURCE_LIST}" ] || ! grep -q "${DOCKER_REPO}" "${DOCKER_SOURCE_LIST}"; then
        info "Configuring Docker repository..."
        echo "deb [arch=amd64 signed-by=${DOCKER_GPG_KEY}] ${DOCKER_REPO} bookworm stable" | \
            tee "${DOCKER_SOURCE_LIST}" >/dev/null || \
            die "Failed to add Docker repository"
    else
        info "Docker repository already configured."
    fi
}

install_docker_and_sshpass() {
    info "Checking Docker and sshpass installation..."

    if ! command -v docker >/dev/null 2>&1; then
        info "Installing Docker..."
        setup_docker_repository
        apt-get update >/dev/null && apt-get install -y docker-ce docker-ce-cli containerd.io >/dev/null 2>>"${ERROR_LOG}" || \
            die "Docker installation failed"
    fi

    if ! systemctl is-active --quiet docker; then
        systemctl enable --now docker || die "Failed to enable Docker service"
    fi

    if ! groups kali | grep -q docker; then
        usermod -aG docker kali || die "Failed to add kali user to docker group"
        info "Added kali user to docker group. Please log out and back in for changes to take effect."
    fi

    # Check if sshpass is installed, and install if necessary
    if ! command -v sshpass >/dev/null 2>&1; then
        info "sshpass not found. Installing sshpass..."
        apt-get install -y sshpass >/dev/null 2>>"${ERROR_LOG}" || \
            die "sshpass installation failed"
    fi
}

################################################################################
# ELK setup and configuration
################################################################################

setup_elk() {
    info "Cloning the ELK installer repository..."

    if [ ! -d "${ELK_PATH}" ]; then
        git clone "${GIT_REPO}" "${ELK_PATH}" 2>>"${ERROR_LOG}" || die "Failed to clone ELK installer repository"
    fi

    cd "${ELK_PATH}" || die "Failed to change to ${ELK_PATH}"

    for key in "${!ENV_VARS[@]}"; do
        sed -i "s/^${key}=.*/${key}=${ENV_VARS[${key}]}/" .env || \
            die "Failed to update ${key} in .env"
    done

    # Attempt to pull Docker images with a retry mechanism
    info "Pulling the Images..."

    if ! docker compose pull >/dev/null 2>>"${ERROR_LOG}"; then
        warn "Initial Docker pull failed, retrying once more..."
        sleep 10  # Optional delay before retry
        docker compose pull >/dev/null 2>>"${ERROR_LOG}" || die "Failed to pull Docker images after retry"
    fi
    
    info "Configuring the images..."
    docker compose up -d elasticsearch kibana setup 2>>"${ERROR_LOG}" || die "Failed to start ELK services"

    info "Waiting for setup to complete..."
    local start_time=$(date +%s)

    while true; do
        if [ "$(($(date +%s) - start_time))" -gt "${SETUP_TIMEOUT}" ]; then
            die "Setup timed out after ${SETUP_TIMEOUT} seconds"
        fi

        if docker inspect -f '{{.State.Status}}' setup 2>/dev/null | grep -q "exited"; then
            break
        fi
        sleep 5
    done

    chmod +x ./scripts/token.sh || die "Failed to make token script executable"
    ./scripts/token.sh >/dev/null || die "Failed to generate token"
    docker compose up -d elastic-agent 2>>"${ERROR_LOG}" || die "Failed to start Elastic Agent"
}

configure_aliases() {
    info "Configuring aliases..."
    local compose_path="${ELK_PATH}/docker-compose.yml"
    local zshrc_file="/home/kali/.zshrc"

    local aliases=(
        "alias elk-start='docker compose -f ${compose_path} start elasticsearch kibana elastic-agent && echo \"\nAccess the Elastic SIEM at: http://localhost:5601\"'"
        "alias elk-stop='docker compose -f ${compose_path} stop'"
        "alias elk-reset='(cd ${ELK_PATH} && docker compose down -v && docker compose up -d elasticsearch kibana setup && echo \"[INFO] Waiting for setup to complete...\" && while [ \"\$(docker inspect -f \"{{.State.Status}}\" setup 2>/dev/null)\" != \"exited\" ]; do sleep 1; done && sudo ./scripts/token.sh && docker compose up -d elastic-agent)'"
    )

    # Add a newline and a comment before appending the aliases
    {
        echo ""
        echo "# ELK aliases"
        for alias in "${aliases[@]}"; do
            echo "${alias}"
        done
    } >> "${zshrc_file}" || die "Failed to add aliases to .zshrc"
}

################################################################################
# Main script execution
################################################################################

main() {
    trap cleanup EXIT
    trap 'error "Error on line $LINENO. Command: $BASH_COMMAND"' ERR

    check_root
    check_ram
    check_dependencies

    command -v docker >/dev/null 2>&1 || install_docker
    setup_elk
    configure_aliases

    info "ELK setup complete!"
    echo
    echo "Available commands:"
    echo "  elk-start  : Starts the ELK services"
    echo "  elk-stop   : Stops the ELK services"
    echo "  elk-reset  : Resets the ELK services"
    echo
    echo "Access the Elastic SIEM at: http://localhost:5601"
}

main "$@"