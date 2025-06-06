#!/bin/bash

set -euo pipefail

################################################################################
# Elastic Stack Docker Compose Deployment Script
# 
# This script deploys Elastic Stack using Docker Compose with configurable
# password and version parameters, then validates container health status.
################################################################################

################################################################################
# Configuration and defaults
################################################################################

readonly SCRIPT_NAME="${0##*/}"
readonly ERROR_LOG=$(mktemp)
readonly ELK_PATH="/opt/elk-installer"
readonly GIT_REPO="https://github.com/kalic-xing/elk-installer.git"
readonly MIN_RAM_MB=3890


# Docker installation configuration
readonly DOCKER_REPO="https://download.docker.com/linux/debian"
readonly DOCKER_GPG_KEY="/etc/apt/keyrings/docker.gpg"
readonly DOCKER_SOURCE_LIST="/etc/apt/sources.list.d/docker.list"

# Default configuration
DEFAULT_PASSWORD="lablab"
DEFAULT_VERSION="8.14.1"
COMPOSE_FILE="${ELK_PATH}/docker-compose.yml"

# Create a Random Kibana Password
KIBANA_PASSWORD=$(openssl rand -base64 12 | tr -d '+/=' | head -c12)

# Container health check configuration
readonly HEALTHY_CONTAINERS=("elasticsearch" "kibana" "elastic-agent")
readonly MAX_HEALTH_CHECK_ATTEMPTS=30
readonly HEALTH_CHECK_INTERVAL=10

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
# Utility functions
################################################################################

usage() {
    cat << EOF
Usage: ${SCRIPT_NAME} [OPTIONS]

Deploy Elastic Stack using Docker Compose with health validation.

OPTIONS:
    --password PASSWORD    Set elastic password (default: ${DEFAULT_PASSWORD})
    --version VERSION      Set Elastic Stack version (default: ${DEFAULT_VERSION})
    -h, --help            Show this help message

EXAMPLES:
    ${SCRIPT_NAME}
    ${SCRIPT_NAME} --password mypassword --version 8.12.0

EOF
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
        die "Insufficient RAM: ${total_ram}MB. For optimal SIEM performance, Consider upgrading to atleast 4GB for efficient operation."
    fi
}

check_container_health() {
    local container_name="$1"
    local health_status
    
    health_status=$(docker inspect --format='{{.State.Health.Status}}' "${container_name}" 2>/dev/null || echo "unknown")
    
    case "${health_status}" in
        "healthy")
            return 0
            ;;
        "unhealthy"|"starting")
            return 1
            ;;
        *)
            # Container might not have health check, check if it's running
            local running_status
            running_status=$(docker inspect --format='{{.State.Running}}' "${container_name}" 2>/dev/null || echo "false")
            [ "${running_status}" = "true" ]
            ;;
    esac
}

wait_for_container_health() {
    local container_name="$1"
    local attempt=1

    while [ ${attempt} -le ${MAX_HEALTH_CHECK_ATTEMPTS} ]; do
        if check_container_health "${container_name}"; then
            return 0
        fi
        
        if [ ${attempt} -eq ${MAX_HEALTH_CHECK_ATTEMPTS} ]; then
            error "Timeout waiting for ${container_name} to become healthy after $((MAX_HEALTH_CHECK_ATTEMPTS * HEALTH_CHECK_INTERVAL)) seconds"
            return 1
        fi
        
        sleep ${HEALTH_CHECK_INTERVAL}
        ((attempt++))
    done
}

################################################################################
# Docker & nxc installation and configuration
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
    info "Setting up Docker repository for Kali Linux..."

    # Ensure keyrings directory exists
    mkdir -p /etc/apt/keyrings

    # Remove existing GPG key if it exists to avoid conflicts
    [ -f "${DOCKER_GPG_KEY}" ] && rm -f "${DOCKER_GPG_KEY}"

    info "Adding Docker's official GPG key..."
    if ! curl -fsSL "${DOCKER_REPO}/gpg" | gpg --dearmor -o "${DOCKER_GPG_KEY}" 2>>"${ERROR_LOG}"; then
        die "Failed to add Docker GPG key"
    fi

    # Detect architecture for proper repository configuration
    local arch
    arch=$(dpkg --print-architecture)

    # Use bookworm (Debian 12) as it's the current stable base for Kali
    local debian_codename="bookworm"

    if [ ! -f "${DOCKER_SOURCE_LIST}" ] || ! grep -q "${DOCKER_REPO}" "${DOCKER_SOURCE_LIST}"; then
        info "Configuring Docker repository for Kali Linux (${arch} architecture)..."
        echo "deb [arch=${arch} signed-by=${DOCKER_GPG_KEY}] ${DOCKER_REPO} ${debian_codename} stable" | \
            tee "${DOCKER_SOURCE_LIST}" >/dev/null || \
            die "Failed to add Docker repository"
    else
        info "Docker repository already configured."
    fi

    # Update package list after adding repository
    info "Updating package list..."
    apt update >/dev/null 2>>"${ERROR_LOG}" || die "Failed to update package list"
}

# Function to check if commands exist
check_commands() {
    local commands=("docker --version" "docker compose version")
    for cmd in "${commands[@]}"; do
        if ! $cmd >/dev/null 2>&1; then
            return 1  # Command missing
        fi
    done
    return 0  # All commands exist
}


install_docker_and_netexec() {
    info "Checking Docker and Netexec installation..."

     # Install Docker and Docker Compose if any commands are missing
    if ! check_commands; then
        info "Installing Docker and Docker Compose..."
        setup_docker_repository
        apt install -y docker-ce docker-ce-cli containerd.io >/dev/null 2>>"${ERROR_LOG}" || \
            die "Docker/Docker Compose installation failed"
    fi

    # Ensure Docker service is running
    if ! systemctl is-active --quiet docker; then
        systemctl enable --now docker || die "Failed to enable Docker service"
    fi

    # Add current user to Docker group if not already a member
    if ! groups kali | grep -q docker; then
        usermod -aG docker kali || die "Failed to add kali user to docker group"
        info "Added kali user to docker group. Please log out and back in for changes to take effect."
    fi

    # Check if netexec is installed, and install if necessary
    if ! command -v nxc >/dev/null 2>&1; then
        info "netexec not found. Installing netexec..."
        apt install -y netexec >/dev/null 2>>"${ERROR_LOG}" || \
            die "netexec installation failed"
    fi
}

################################################################################
# Clone Repository
################################################################################

clone_elk() {
    info "Cloning the ELK installer repository..."

    if [ -d "${ELK_PATH}" ]; then
        rm -rf "${ELK_PATH}"
    fi

    git clone "${GIT_REPO}" "${ELK_PATH}" 2>>"${ERROR_LOG}" || die "Failed to clone ELK installer repository"

    cd "${ELK_PATH}" || die "Failed to change to ${ELK_PATH}"

    info "Creating .env configuration file..."
    cat > .env << EOF
ELASTIC_PASSWORD=${ELASTIC_PASSWORD}
STACK_VERSION=${STACK_VERSION}
KIBANA_PASSWORD=${KIBANA_PASSWORD}
EOF

    info "Configuration file created successfully"
}

validate_all_containers() {
    local failed_containers=()
    
    info "Validating container health status..."
    
    for container in "${HEALTHY_CONTAINERS[@]}"; do
        if ! wait_for_container_health "${container}"; then
            failed_containers+=("${container}")
        fi
    done
    
    if [ ${#failed_containers[@]} -gt 0 ]; then
        error "The following containers failed health checks: ${failed_containers[*]}"
        return 1
    fi
    
    info "All containers are healthy and running successfully"
    return 0
}

execute_docker_compose() {
    local compose_cmd
    
    # Determine docker compose command (newer docker compose vs docker-compose)
    if docker compose version >/dev/null 2>&1; then
        compose_cmd="docker compose"
    else
        compose_cmd="docker-compose"
    fi
    
    if [ ! -f "${COMPOSE_FILE}" ]; then
        die "Docker Compose file '${COMPOSE_FILE}' not found in current directory"
    fi
    
    # Attempt to pull Docker images with a retry mechanism
    info "Pulling the Images..."
    if ! ${compose_cmd} -f ${COMPOSE_FILE} pull >/dev/null 2>>"${ERROR_LOG}"; then
        warn "Initial Docker pull failed, retrying once more..."
        sleep 10  # Optional delay before retry
        ${compose_cmd} -f ${COMPOSE_FILE} pull >/dev/null 2>>"${ERROR_LOG}" || die "Failed to pull Docker images after retry"
    fi
    
    # Create the elk network if it doesn't exist
    if ! docker network ls --format "{{.Name}}" | grep -q "^elk$"; then
        if ! docker network create elk >/dev/null 2>"${ERROR_LOG}"; then
            error "Docker network create failed"
            [ -s "${ERROR_LOG}" ] && error "Docker network create failed: $(cat "${ERROR_LOG}")"
            return 1
        fi
    fi

    info "Starting Elastic Stack deployment..."
    if ! ${compose_cmd} -f ${COMPOSE_FILE} --profile setup up -d >/dev/null 2>"${ERROR_LOG}"; then
        error "Docker Compose deployment failed"
        [ -s "${ERROR_LOG}" ] && error "Docker Compose error: $(cat "${ERROR_LOG}")"
        return 1
    fi
    
    info "Docker Compose deployment completed successfully"
    return 0
}

display_deployment_info() {
    info "Elastic Stack deployment completed successfully. Displaying access information..."

    # Create formatted output with colors
    local info_color="\033[0;36m"    # Cyan for info sections
    local value_color="\033[1;37m"   # Bold white for values
    local reset_color="\033[0m"

    echo
    echo -e "${info_color}ELK Stack Credentials:${reset_color}"
    echo -e "    ${info_color}Elastic Username:${reset_color} ${value_color}elastic${reset_color}"
    echo -e "    ${info_color}Elastic Password:${reset_color} ${value_color}${ELASTIC_PASSWORD}${reset_color}"
    echo
    echo
    echo -e "${info_color}Access the Elastic SIEM at:${reset_color} ${value_color}http://localhost:5601${reset_color}"
    echo
}

################################################################################
# Argument parsing
################################################################################

parse_arguments() {
    ELASTIC_PASSWORD="${DEFAULT_PASSWORD}"
    STACK_VERSION="${DEFAULT_VERSION}"
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --password)
                [ -n "${2:-}" ] || die "Password argument requires a value"
                ELASTIC_PASSWORD="$2"
                shift 2
                ;;
            --version)
                [ -n "${2:-}" ] || die "Version argument requires a value"
                STACK_VERSION="$2"
                shift 2
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                die "Unknown argument: $1. Use --help for usage information."
                ;;
        esac
    done
    
    info "Configuration: Password=*****, Version=${STACK_VERSION}"
}

################################################################################
# Main execution
################################################################################

main() {
    trap cleanup EXIT ERR INT TERM
    parse_arguments "$@"

    info "Starting Elastic Stack deployment script"

    check_root
    check_ram
    install_docker_and_netexec
    clone_elk
    execute_docker_compose
    validate_all_containers
    display_deployment_info

}

# Execute main function
main "$@"