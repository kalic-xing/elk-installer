#!/bin/bash

set -e  # Exit immediately if a command exits with a non-zero status

# Ensure the script is run as root
if (( $EUID != 0 )); then
  echo "Please run as root"
  exit 1
fi

# Variables
host="siem01"
kibana_yml='/etc/kibana/kibana.yml'
elasticsearch_yml='/etc/elasticsearch/elasticsearch.yml'
elastic_user="offsec"
elastic_pass="lablab"

# Function to check if a tool exists and install it if it doesn't
ensure_tool() {
  if ! command -v "$1" &> /dev/null; then
    echo "[-] $1 is not installed. Installing $1..."
    apt-get update -qq 
    apt-get install -y "$1" &>/dev/null
  fi
}

# Ensure required tools are installed
ensure_tool curl
ensure_tool gpg

# Check if the Elasticsearch repository is already added
if [ ! -d /etc/apt/sources.list.d ] || ! ls /etc/apt/sources.list.d/elastic* &> /dev/null; then
  echo "[+] Adding Elasticsearch repository..."
  curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --dearmor -o /usr/share/keyrings/elastic.gpg
  echo "deb [signed-by=/usr/share/keyrings/elastic.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | tee /etc/apt/sources.list.d/elastic-8.x.list &>/dev/null
fi

# Install Elasticsearch & Kibana
echo "[+] Installing Elasticsearch and Kibana..."
apt-get update -qq
apt-get install -y elasticsearch kibana &>/dev/null

# Configure Elasticsearch for basic authentication
echo "[+] Configuring Elasticsearch yml file..."
sed -i 's/^[#]*\s*network.host: .*/network.host: 0.0.0.0/' $elasticsearch_yml
sed -i '/xpack.security.http.ssl:/,/enabled:/ s/enabled: true/enabled: false/' $elasticsearch_yml

# Start Elasticsearch
echo "[+] Starting Elasticsearch service..."
systemctl start elasticsearch

# Reset the kibana_system password
echo "[+] Resetting kibana_system password..."
kibana_pass=$(echo y | /usr/share/elasticsearch/bin/elasticsearch-reset-password -u kibana_system -a -s 2>/dev/null | awk '{print $NF}')

# Configure Kibana
echo "[+] Configuring Kibana yml file..."
sed -i "s|#elasticsearch.hosts: \[\"http://localhost:9200\"\]|elasticsearch.hosts: [\"http://$host:9200\"]|" $kibana_yml
sed -i 's/^[#]*\s*elasticsearch.username: .*/elasticsearch.username: "kibana_system"/' $kibana_yml
sed -i "s|#elasticsearch.password: \"pass\"|elasticsearch.password: \"$kibana_pass\"|" $kibana_yml

# Create the offsec user and set the password
echo "[+] Creating the offsec user and setting the password..."
/usr/share/elasticsearch/bin/elasticsearch-users useradd $elastic_user -p "$elastic_pass" -r 'superuser'

# Start Kibana
echo "[+] Starting Kibana..."
systemctl start kibana

# Generate keys for the detection rules
echo "[+] Generating the keys for the detection rules..."
{
  printf "\n# =================== Generated Keys ===================\n"
  /usr/share/kibana/bin/kibana-encryption-keys generate | tail -n4 | head -n3
} >> $kibana_yml

# Restart Kibana
echo "[+] Restarting Kibana..."
systemctl restart kibana

# Modify the 3rd line in hosts file
sed -i "3i 127.0.0.1\t$host" /etc/hosts

# Sleep for 5 seconds to let Kibana fully start
sleep 5

echo "[+] Kibana is now accessible via:"
echo -e "\t[*] Url: http://$host:5601"
echo -e "\t[*] Username: $elastic_user"
echo -e "\t[*] Password: $elastic_pass"

# Define the ELK management script content
cat << 'EOF' | tee /usr/local/bin/elk > /dev/null
#!/bin/bash

if [ $# -eq 0 ] || [[ $EUID -ne 0 ]]; then
  if [ $# -eq 0 ]; then
    echo "Usage: elk {start|stop}"
    echo "Please provide an argument to start or stop the ELK services."
  else
    echo "This script must be run as root. Please use sudo elk {start|stop}"
  fi
  exit 1
fi

# Start the SIEM
if [ "$1" == "start" ]; then
  echo "[+] Starting the SIEM services..."
  systemctl start elasticsearch
  systemctl start kibana

  sleep 10
  echo "[+] SIEM is accessible via http://siem01:5601"

# Stop the SIEM
elif [ "$1" == "stop" ]; then
  echo "[+] Stopping the SIEM services in the background..."
  nohup systemctl stop kibana > /dev/null 2>&1 &
  nohup systemctl stop elasticsearch > /dev/null 2>&1 &
  wait
  echo "[+] SIEM successfully stopped"
else
  echo "Invalid argument. Use 'start' or 'stop'."
  exit 1
fi
EOF

# Make the ELK management script executable
chmod +x /usr/local/bin/elk

echo "[+] To start or stop the SIEM, use the command: sudo elk {start|stop}"