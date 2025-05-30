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

# Default configuration
DEFAULT_PASSWORD="lablab"
DEFAULT_VERSION="9.0.1"
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
        warn "Insufficient RAM: ${total_ram}MB. For optimal SIEM performance, Consider upgrading to atleast 4GB after installation for efficient operation."
        sleep 3
    fi
}

validate_docker_environment() {
    if ! command -v docker >/dev/null 2>&1; then
        die "Docker is not installed or not in PATH"
    fi

    if ! command -v docker compose >/dev/null 2>&1 && ! docker compose version >/dev/null 2>&1; then
        die "Docker Compose is not installed or not available"
    fi

    if [ ! -f "${COMPOSE_FILE}" ]; then
        die "Docker Compose file '${COMPOSE_FILE}' not found in current directory"
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
    
    info "Waiting for ${container_name} to become healthy..."
    
    while [ ${attempt} -le ${MAX_HEALTH_CHECK_ATTEMPTS} ]; do
        if check_container_health "${container_name}"; then
            info "${container_name} is healthy"
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

install_docker_and_netexec() {
    info "Checking Docker and Netexec installation..."

    # Check if Docker is installed, and install if necessary
    if ! command -v docker >/dev/null 2>&1; then
        info "Installing Docker..."
        setup_docker_repository
        apt update >/dev/null && apt install -y docker-ce docker-ce-cli containerd.io >/dev/null 2>>"${ERROR_LOG}" || \
            die "Docker installation failed"
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

    if [ ! -d "${ELK_PATH}" ]; then
        git clone "${GIT_REPO}" "${ELK_PATH}" 2>>"${ERROR_LOG}" || die "Failed to clone ELK installer repository"
    fi

    cd "${ELK_PATH}" || die "Failed to change to ${ELK_PATH}"

    for key in "${!ENV_VARS[@]}"; do
        sed -i "s/^${key}=.*/${key}=${ENV_VARS[${key}]}/" .env || \
            die "Failed to update ${key} in .env"
    done
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
       
    # Attempt to pull Docker images with a retry mechanism
    info "Pulling the Images..."
    if ! ${compose_cmd} -f ${COMPOSE_FILE} pull >/dev/null 2>>"${ERROR_LOG}"; then
        warn "Initial Docker pull failed, retrying once more..."
        sleep 10  # Optional delay before retry
        ${compose_cmd} -f ${COMPOSE_FILE} pull >/dev/null 2>>"${ERROR_LOG}" || die "Failed to pull Docker images after retry"
    fi
    
    info "Starting Elastic Stack deployment..."
    if ! ${compose_cmd} -f ${COMPOSE_FILE} up -d >/dev/null 2>"${ERROR_LOG}"; then
        error "Docker Compose deployment failed"
        [ -s "${ERROR_LOG}" ] && error "Docker Compose error: $(cat "${ERROR_LOG}")"
        return 1
    fi
    
    info "Docker Compose deployment completed successfully"
    return 0
}

################################################################################
# Argument parsing
################################################################################

parse_arguments() {
    local password="${DEFAULT_PASSWORD}"
    local version="${DEFAULT_VERSION}"
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --password)
                [ -n "${2:-}" ] || die "Password argument requires a value"
                password="$2"
                shift 2
                ;;
            --version)
                [ -n "${2:-}" ] || die "Version argument requires a value"
                version="$2"
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
    
    # Export environment variables for Docker Compose
    export ELASTIC_PASSWORD="${password}"
    export STACK_VERSION="${version}"
    export KIBANA_PASSWORD="${KIBANA_PASSWORD}"

    info "Configuration: Password=*****, Version=${version}"
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
    validate_docker_environment
    clone_elk
    execute_docker_compose
    validate_all_containers
    
    info "Elastic Stack deployment completed successfully"
}

# Execute main function
main "$@"