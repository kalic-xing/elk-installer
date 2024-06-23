
# ELK Installer

A guide for setting up Elasticsearch, Kibana and Fleet. You can choose between two methods: using a Docker Compose setup or running a bash script. Both methods provide a straightforward and efficient way to get the ELK stack up and running.

:exclamation: __Do not use this methods in production environment.__

## Prerequisites

- Debian-based operating system (e.g., Debian, Ubuntu)
- Basic knowledge of command-line interface
- For Docker setup: [Docker and Docker Compose installed](https://docs.docker.com/desktop/) 


## Using Bash Script

```sh
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/kalic-xing/elk-installer/main/elk.sh"
```

### Usage
- After installation, access Kibana at http://siem01:5601  
- Elasticsearch will be running on port 9200
- sudo elk {start|stop} to manage ELK


## Using Docker Compose

1. Clone the repository:

```
git clone git@github.com:kalic-xing/elk-installer.git
cd elk-installer/
```

_Update ELASTIC_PASSWORD, KIBANA_PASSWORD & STACK_VERSION in `.env` file_

2. Run Docker Compose:

```
docker compose up -d elasticsearch elasticsearch-init kibana token-init
```

_Wait for token-init to reach exit status before proceeding with the next command._

3. Run the Fleet service:

```
chmod +x ./scripts/token.sh && ./scripts/token.sh && docker compose up -d elastic-agent
```

## Todo

- [ ]  Find a way to update FLEET_SERVER_SERVICE_TOKEN env before executing the container



## Contributing

We welcome contributions to improve this project! Please fork the repository and create a pull request with your changes.


## License

This project is licensed under the MIT License. See the `LICENSE` file for details.


