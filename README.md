# ELK Installer

A comprehensive automation suite for setting up and managing Elasticsearch, Kibana, and Fleet agents. This installer provides a complete SIEM (Security Information and Event Management) solution with automated deployment, agent management, and system monitoring capabilities.

> ❗ **Important**: Do not use these methods in a production environment. This installer is designed for development, testing, and learning purposes.

## Overview

This script automates the setup of an ELK (Elasticsearch, Logstash, Kibana) stack on a target machine, ensuring the system meets requirements by checking for at least 3.8 GB of RAM and root privileges. It installs Docker if it's not already present, configuring it to run on boot and adding the current user to the Docker group. The script then clones the ELK installer repository, updates key environment variables in the .env file, and uses Docker Compose to download and configure Elasticsearch, Kibana, and Elastic Agent. Upon completion, users are provided with instructions on how to access the Elastic SIEM interface. This script simplifies the entire process, from system checks to service management, providing a seamless and efficient ELK stack setup.

## Prerequisites

- **Operating System**: Kali Linux distribution
- **RAM**: Minimum 4GB (3.8GB required for optimal performance)
- **Storage**: At least 10GB free disk space
- **Network**: Internet connectivity for downloading components
- **Privileges**: Root or sudo access
- **Basic knowledge**: Command-line interface familiarity

### Additional Requirements for Agent Deployment
- **For Windows targets**: `impacket-smbclient`, `netexec` (nxc)
- **For Linux targets**: `sshpass`, `ssh`, `scp`

## Quick Start

### One-Line Installation

Deploy the complete ELK stack with a single command:

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/kalic-xing/elk-installer/main/install.sh)"
```

### Installation Options

You can customize the installation with additional parameters:

```bash
# Install with custom password
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/kalic-xing/elk-installer/main/install.sh) --password 'myCustomPassword123'"

# Install specific version
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/kalic-xing/elk-installer/main/install.sh) --version '9.0.3'"

# Install with both custom password and version
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/kalic-xing/elk-installer/main/install.sh) --password 'myPassword' --version '9.0.3'"
```

### Post-Installation Access

After successful installation:
- **Kibana Interface**: http://localhost:5601
- **Elasticsearch API**: http://localhost:9200
- **Default Username**: `elastic`
- **Password**: Generated automatically (displayed during installation)

## Management Scripts

The installer includes three powerful management scripts located in `/opt/elk-installer/`:

### 1. ELK Stack Management (`manage.sh`)

Comprehensive management of your ELK stack deployment:

```bash
# Start all services
sudo /opt/elk-installer/manage.sh start

# Stop all services
sudo /opt/elk-installer/manage.sh stop

# Restart all services
sudo /opt/elk-installer/manage.sh restart

# Check detailed status
sudo /opt/elk-installer/manage.sh status

# Monitor health of all containers
sudo /opt/elk-installer/manage.sh health

# View logs
sudo /opt/elk-installer/manage.sh logs

# Follow logs in real-time
sudo /opt/elk-installer/manage.sh logs -f

# Complete cleanup (removes ALL data)
sudo /opt/elk-installer/manage.sh clean
```

**Available Commands:**
- `start`: Initialize and start all ELK services
- `stop`: Gracefully stop all running services
- `restart`: Stop and restart all services
- `status`: Display comprehensive container status
- `health`: Perform health checks on all containers
- `logs`: Show recent logs from all services
- `clean`: **⚠️ WARNING**: Removes all data including Elasticsearch indices

### 2. Fleet Agent Deployment (`install_agent.sh`)

Automated deployment of Elastic agents to remote Windows and Linux systems:

#### Basic Usage

```bash
# Deploy to Windows target
sudo /opt/elk-installer/install_agent.sh -arch Windows -username administrator -password 'P@ssw0rd!' -target 192.168.1.100

# Deploy to Linux target
sudo /opt/elk-installer/install_agent.sh -arch Linux -username root -password 'password123' -target 192.168.1.101
```

#### Advanced Options

```bash
# With verbose logging
sudo /opt/elk-installer/install_agent.sh -arch Linux -username ubuntu -password 'mypass' -target 10.0.0.50 -v

# With custom TUN0 IP (for VPN environments)
sudo /opt/elk-installer/install_agent.sh -arch Linux -username ubuntu -password 'mypass' -target 10.0.0.50 -tun0 192.168.1.10

# Get help
sudo /opt/elk-installer/install_agent.sh -h
```

**Parameters:**
- `-arch <Windows|Linux>`: Target operating system
- `-username <user>`: Username for remote authentication
- `-password <pass>`: Password for remote authentication
- `-target <ip>`: Target machine IP address
- `-tun0 <ip>`: (Optional) Specify TUN0 IP address
- `-v, --verbose`: Enable verbose logging
- `-h, --help`: Display help information

**What it does:**
- Auto-detects Elastic Agent version from running containers
- Downloads appropriate agent packages for target OS
- For Windows: Installs Sysmon for enhanced logging
- Uploads and executes installation scripts remotely
- Automatically enrolls agents with Fleet management
- Provides detailed logging and error handling

## Alternative: Docker Compose Method

For advanced users who prefer manual control:

### 1. Clone Repository

```bash
git clone https://github.com/kalic-xing/elk-installer.git
cd elk-installer/
```

### 2. Configure Environment

```bash
cat << EOF >> .env
ELASTIC_PASSWORD=your_secure_password
KIBANA_PASSWORD=your_kibana_password
STACK_VERSION=your_version
EOF
```

### 3. Deploy Stack

```bash
# Create network
docker network create elk

# Deploy with setup profile
docker compose --profile setup up -d
```

## Features

### Security Features
- **Automatic SSL/TLS configuration** for Elasticsearch and Kibana
- **Randomly generated secure passwords** for system accounts
- **Role-based access control** with Elasticsearch security
- **Fleet agent enrollment tokens** for secure agent communication

### Monitoring Capabilities
- **Real-time log ingestion** from multiple sources
- **System metrics collection** (CPU, memory, disk, network)
- **Security event monitoring** with Sysmon integration (Windows)
- **Fleet management** for centralized agent administration

### Automated Operations
- **Health monitoring** with automatic retry mechanisms
- **Container lifecycle management** with proper dependency handling
- **Automatic cleanup** of temporary setup containers
- **Version compatibility** checking and validation

## System Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Elasticsearch │    │     Kibana      │    │  Elastic Agent  │
│                 │    │                 │    │                 │
│  Data Storage   │◄───┤  Visualization  │    │  Data Collection│
│  Search Engine  │    │  Management UI  │    │  Log Forwarding │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         ▲                        ▲                        │
         │                        │                        │
         └────────────────────────┼────────────────────────┘
                                  │
                         ┌─────────────────┐
                         │  Fleet Server   │
                         │                 │
                         │ Agent Management│
                         │ Policy Control  │
                         └─────────────────┘
```

## Troubleshooting

### Common Issues

#### Installation Problems
```bash
# Check system requirements
free -h  # Verify RAM (need 4GB+)
df -h    # Check disk space (need 10GB+)

# Check Docker status
sudo systemctl status docker

# View installation logs
sudo journalctl -u docker
```

#### Service Issues
```bash
# Check container status
sudo /opt/elk-installer/manage.sh status

# View service logs
sudo /opt/elk-installer/manage.sh logs

# Restart services
sudo /opt/elk-installer/manage.sh restart
```

#### Agent Deployment Issues
```bash
# Test connectivity to target
ping <target_ip>

# For Windows targets
nxc smb <target_ip> -u <username> -p <password>

# For Linux targets
ssh <username>@<target_ip>

# Check enrollment tokens
cat /opt/elk-installer/tokens/enrollment_tokens.txt
```

### Log Locations
- **ELK Stack logs**: Available via `manage.sh logs` command
- **Agent deployment logs**: Displayed during installation with `-v` flag
- **System logs**: `/var/log/syslog` or `journalctl`

## Network Configuration

### Default Ports
- **Kibana**: 5601 (HTTP)
- **Elasticsearch**: 9200 (HTTP), 9300 (Transport)
- **Fleet Server**: 8220 (HTTPS)

### Firewall Configuration
```bash
# Allow Kibana access
sudo ufw allow 5601/tcp

# Allow Elasticsearch (if needed externally)
sudo ufw allow 9200/tcp

# Allow Fleet Server for agents
sudo ufw allow 8220/tcp
```

## Security Considerations

### Default Security Measures
- All inter-node communication uses TLS encryption
- Authentication required for all API access
- Randomly generated passwords for system accounts
- Network isolation using Docker networks

### Recommended Additional Steps
1. **Change default passwords** after installation
2. **Configure proper firewall rules** for your environment
3. **Set up proper backup procedures** for Elasticsearch data
4. **Monitor system resources** and set up alerting
5. **Regular updates** of Elastic Stack components

## Support and Contributing

### Getting Help
- Check the troubleshooting section above
- Review container logs for specific error messages
- Ensure all prerequisites are met
- Verify network connectivity and credentials

### Contributing
We welcome contributions to improve this project! 

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/improvement`)
3. Commit your changes (`git commit -am 'Add new feature'`)
4. Push to the branch (`git push origin feature/improvement`)
5. Create a Pull Request

### Reporting Issues
When reporting issues, please include:
- Operating system and version
- Error messages or logs
- Steps to reproduce the problem
- System specifications (RAM, disk space, etc.)

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

---

**⚠️ Security Notice**: This installer is designed for development and testing environments. For production deployments, please review and implement additional security measures appropriate for your organization's requirements.