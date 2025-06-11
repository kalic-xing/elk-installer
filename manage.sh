#!/bin/bash

set -euo pipefail

################################################################################
# Elastic Stack Management Script
#
# This script provides management operations for the Elastic Stack deployment
# including start, stop, restart, status monitoring, and cleanup operations.
################################################################################

################################################################################
# Configuration and defaults
################################################################################

readonly SCRIPT_NAME="${0##*/}"
readonly ERROR_LOG=$(mktemp)
readonly ELK_PATH="/opt/elk-installer"
readonly COMPOSE_FILE="${ELK_PATH}/docker-compose.yml"
readonly ENV_FILE="${ELK_PATH}/.env"

# Container monitoring configuration
readonly MAIN_CONTAINERS=("elasticsearch" "kibana" "elastic-agent")
readonly SETUP_CONTAINERS=("elasticsearch-setup" "kibana-setup")
readonly HEALTH_CHECK_TIMEOUT=120
readonly HEALTH_CHECK_INTERVAL=5

################################################################################
# Logging and error handling
################################################################################

# ANSI color codes for log levels
COLOR_RESET="\033[0m"
COLOR_INFO="\033[0;32m"    # Green for INFO
COLOR_WARN="\033[0;33m"    # Yellow for WARNING
COLOR_ERROR="\033[0;31m"   # Red for ERROR
COLOR_SUCCESS="\033[1;32m" # Bold Green for SUCCESS

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

success() {
    log "SUCCESS" "${COLOR_SUCCESS}" "$@"
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
Usage: ${SCRIPT_NAME} [COMMAND] [OPTIONS]

Manage Elastic Stack deployment with health monitoring and proper cleanup.

COMMANDS:
    start       Start the ELK stack services
    stop        Stop the ELK stack services
    restart     Restart the ELK stack services
    status      Show detailed status of all containers
    logs        Show logs from services (use -f for follow mode)
    clean       Stop services and remove all data volumes
    health      Check health status of all running containers

OPTIONS:
    -f, --follow    Follow logs in real-time (use with logs command)
    -h, --help      Show this help message

EXAMPLES:
    ${SCRIPT_NAME} start
    ${SCRIPT_NAME} logs -f
    ${SCRIPT_NAME} status
    ${SCRIPT_NAME} clean

NOTES:
    - The 'clean' command will remove ALL data including Elasticsearch indices
    - Services will automatically wait for dependencies to be healthy
    - Setup containers are automatically cleaned after successful deployment

EOF
}

################################################################################
# System checks
################################################################################

check_requirements() {
    if [ ! -f "${COMPOSE_FILE}" ]; then
        die "Docker Compose file not found: ${COMPOSE_FILE}"
    fi

    if [ ! -f "${ENV_FILE}" ]; then
        die "Environment file not found: ${ENV_FILE}. Please run install.sh first."
    fi

    if ! command -v docker >/dev/null 2>&1; then
        die "Docker is not installed or not in PATH"
    fi

    if ! docker info >/dev/null 2>&1; then
        die "Docker daemon is not running or not accessible"
    fi
}

get_compose_cmd() {
    if docker compose version >/dev/null 2>&1; then
        echo "docker compose"
    else
        echo "docker-compose"
    fi
}

change_to_elk_directory() {
    if [ ! -d "${ELK_PATH}" ]; then
        die "ELK installation directory not found: ${ELK_PATH}"
    fi

    cd "${ELK_PATH}" || die "Failed to change to ELK directory: ${ELK_PATH}"
}

################################################################################
# Container health and status functions
################################################################################

check_container_health() {
    local container_name="$1"
    local health_status

    if ! docker ps --format "{{.Names}}" | grep -q "^${container_name}$"; then
        echo "not_running"
        return 1
    fi

    health_status=$(docker inspect --format='{{.State.Health.Status}}' "${container_name}" 2>/dev/null || echo "unknown")

    case "${health_status}" in
        "healthy")
            echo "healthy"
            return 0
            ;;
        "unhealthy")
            echo "unhealthy"
            return 1
            ;;
        "starting")
            echo "starting"
            return 1
            ;;
        *)
            # Container might not have health check, check if it's running
            local running_status
            running_status=$(docker inspect --format='{{.State.Running}}' "${container_name}" 2>/dev/null || echo "false")
            if [ "${running_status}" = "true" ]; then
                echo "running"
                return 0
            else
                echo "stopped"
                return 1
            fi
            ;;
    esac
}

wait_for_container_health() {
    local container_name="$1"
    local timeout="${2:-${HEALTH_CHECK_TIMEOUT}}"
    local attempt=0

    while [ ${attempt} -lt $((timeout / HEALTH_CHECK_INTERVAL)) ]; do
        local status
        status=$(check_container_health "${container_name}")

        case "${status}" in
            "healthy"|"running")
                return 0
                ;;
            "unhealthy")
                error "${container_name} is unhealthy"
                return 1
                ;;
            "not_running"|"stopped")
                error "${container_name} is not running"
                return 1
                ;;
            "starting")
                # Container is starting, continue waiting
                ;;
        esac

        sleep ${HEALTH_CHECK_INTERVAL}
        ((attempt++))

        # Show progress every 30 seconds
        if [ $((attempt * HEALTH_CHECK_INTERVAL % 30)) -eq 0 ]; then
            info "Still waiting for ${container_name}... ($((attempt * HEALTH_CHECK_INTERVAL))s elapsed)"
        fi
    done

    error "Timeout waiting for ${container_name} to become healthy after ${timeout} seconds"
    return 1
}

################################################################################
# Main operations
################################################################################

start_services() {
    local compose_cmd
    compose_cmd=$(get_compose_cmd)

    info "Starting Elastic Stack services..."

    if ! ${compose_cmd} -f "${COMPOSE_FILE}" up -d 2>"${ERROR_LOG}"; then
        error "Failed to start services"
        [ -s "${ERROR_LOG}" ] && error "Docker Compose error: $(cat "${ERROR_LOG}")"
        return 1
    fi

    success "Services started successfully"

    # Wait for main containers to be healthy
    info "Waiting for the containers to become healthy..."

    local failed_containers=()
    for container in "${MAIN_CONTAINERS[@]}"; do
        if ! wait_for_container_health "${container}"; then
            failed_containers+=("${container}")
        fi
    done

    if [ ${#failed_containers[@]} -gt 0 ]; then
        error "The following containers failed to become healthy: ${failed_containers[*]}"
        warn "Check logs with: ${SCRIPT_NAME} logs"
        return 1
    fi

    success "All services are healthy and running"
    info "Kibana is available at: http://localhost:5601"

    # Display credentials if available
    if [ -f "${ENV_FILE}" ]; then
        local elastic_password
        elastic_password=$(grep "ELASTIC_PASSWORD=" "${ENV_FILE}" | cut -d= -f2)
        if [ -n "${elastic_password}" ]; then
            echo
            info "Login credentials:"
            echo "  Username: elastic"
            echo "  Password: ${elastic_password}"
        fi
    fi
}

stop_services() {
    local compose_cmd
    compose_cmd=$(get_compose_cmd)

    info "Stopping Elastic Stack services..."

    if ! ${compose_cmd} -f "${COMPOSE_FILE}" down 2>"${ERROR_LOG}"; then
        error "Failed to stop services"
        [ -s "${ERROR_LOG}" ] && error "Docker Compose error: $(cat "${ERROR_LOG}")"
        return 1
    fi

    success "Services stopped successfully"
}

restart_services() {
    info "Restarting Elastic Stack services..."
    stop_services
    start_services
}

show_status() {
    local compose_cmd
    compose_cmd=$(get_compose_cmd)

    info "Checking container status..."
    echo

    # Show main containers
    echo -e "${COLOR_INFO}Main Services:${COLOR_RESET}"
    ${compose_cmd} -f "${COMPOSE_FILE}" ps 2>/dev/null || true

    echo
    echo -e "${COLOR_INFO}Health Status:${COLOR_RESET}"
    for container in "${MAIN_CONTAINERS[@]}"; do
        local status
        status=$(check_container_health "${container}")
        local status_color

        case "${status}" in
            "healthy"|"running") status_color="${COLOR_SUCCESS}" ;;
            "starting") status_color="${COLOR_WARN}" ;;
            *) status_color="${COLOR_ERROR}" ;;
        esac

        printf "  %-15s %b%s%b\n" "${container}:" "${status_color}" "${status}" "${COLOR_RESET}"
    done

    # Show setup containers if they exist
    local setup_exist=false
    for container in "${SETUP_CONTAINERS[@]}"; do
        if docker ps -a --format "{{.Names}}" | grep -q "^${container}$"; then
            if [ "${setup_exist}" = false ]; then
                echo
                echo -e "${COLOR_WARN}Setup Containers (should be cleaned):${COLOR_RESET}"
                setup_exist=true
            fi
            local container_status
            container_status=$(docker ps -a --format "{{.Names}}\t{{.Status}}" | grep "^${container}" | cut -f2)
            printf "  %-20s %s\n" "${container}:" "${container_status}"
        fi
    done
}

show_logs() {
    local compose_cmd
    compose_cmd=$(get_compose_cmd)
    local follow_flag=""

    # Check if follow flag is provided
    if [ "${1:-}" = "-f" ] || [ "${1:-}" = "--follow" ]; then
        follow_flag="-f"
        info "Following logs from all services (Ctrl+C to stop)..."
    else
        info "Showing recent logs from all services..."
    fi

    ${compose_cmd} -f "${COMPOSE_FILE}" logs ${follow_flag}
}

check_health() {
    info "Performing health check on all containers..."
    echo

    local all_healthy=true

    for container in "${MAIN_CONTAINERS[@]}"; do
        local status
        status=$(check_container_health "${container}")

        case "${status}" in
            "healthy"|"running")
                echo -e "✅ ${container}: ${COLOR_SUCCESS}${status}${COLOR_RESET}"
                ;;
            "starting")
                echo -e "🔄 ${container}: ${COLOR_WARN}${status}${COLOR_RESET}"
                all_healthy=false
                ;;
            *)
                echo -e "❌ ${container}: ${COLOR_ERROR}${status}${COLOR_RESET}"
                all_healthy=false
                ;;
        esac
    done

    echo
    if [ "${all_healthy}" = true ]; then
        success "All containers are healthy"
        return 0
    else
        warn "Some containers are not healthy"
        return 1
    fi
}

clean_environment() {
    local compose_cmd
    compose_cmd=$(get_compose_cmd)

    warn "This will remove ALL data including Elasticsearch indices and Kibana dashboards!"
    warn "This action cannot be undone!"
    echo
    read -p "Are you sure you want to continue? Type 'yes' to confirm: " -r

    if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
        info "Operation cancelled"
        return 0
    fi

    info "Performing complete cleanup..."

    # Stop and remove everything including volumes
    if ! ${compose_cmd} -f "${COMPOSE_FILE}" down -v 2>"${ERROR_LOG}"; then
        error "Failed to clean environment"
        [ -s "${ERROR_LOG}" ] && error "Docker Compose error: $(cat "${ERROR_LOG}")"
        return 1
    fi

    # Clean up any remaining setup containers
    cleanup_setup_containers

    success "Environment cleaned successfully"
    info "All data has been removed. Next startup will be a fresh installation."
}

################################################################################
# Argument parsing
################################################################################

parse_arguments() {
    local command=""
    local follow_logs=false

    while [[ $# -gt 0 ]]; do
        case $1 in
            start|stop|restart|status|logs|clean|health)
                [ -z "${command}" ] || die "Multiple commands specified. Use --help for usage."
                command="$1"
                shift
                ;;
            -f|--follow)
                follow_logs=true
                shift
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

    [ -n "${command}" ] || die "No command specified. Use --help for usage information."

    # Use global variables instead of trying to return multiple values
    PARSED_COMMAND="${command}"
    FOLLOW_LOGS="${follow_logs}"
}

################################################################################
# Main execution
################################################################################

main() {
    trap cleanup EXIT ERR INT TERM

    # Initialize global variables for argument parsing
    PARSED_COMMAND=""
    FOLLOW_LOGS=false

    # Parse arguments
    parse_arguments "$@"

    info "Starting ELK Stack management operation: ${PARSED_COMMAND}"

    check_requirements
    change_to_elk_directory

    case "${PARSED_COMMAND}" in
        start)
            start_services
            ;;
        stop)
            stop_services
            ;;
        restart)
            restart_services
            ;;
        status)
            show_status
            ;;
        logs)
            if [ "${FOLLOW_LOGS}" = true ]; then
                show_logs "-f"
            else
                show_logs
            fi
            ;;
        clean)
            clean_environment
            ;;
        health)
            check_health
            ;;
        *)
            die "Unknown command: ${PARSED_COMMAND}"
            ;;
    esac
}

# Execute main function
main "$@"