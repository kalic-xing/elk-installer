#!/bin/bash

# Define the file and token path
FILE="docker-compose.yml"
TOKEN_FILE="tokens/enrollment_tokens.txt"

# Run the sed command
sed -i.bak "s|FLEET_SERVER_SERVICE_TOKEN=.*|FLEET_SERVER_SERVICE_TOKEN=$(grep "fleet-service-token" "$TOKEN_FILE" | cut -d ':' -f2)|" $FILE

# Check if the sed command was successful
if [ $? -eq 0 ]; then  
  # Remove the .bak file
  rm "${FILE}.bak"
else
  echo "Failed to update the environment variable FLEET_SERVER_SERVICE_TOKEN in $FILE."
fi