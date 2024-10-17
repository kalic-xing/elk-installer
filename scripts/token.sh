#!/bin/bash

# Define the file and token path
FILE="docker-compose.yml"
TOKEN_FILE="tokens/token.txt"

# Run the sed command
sed -i.bak "s|FLEET_SERVER_SERVICE_TOKEN=.*|FLEET_SERVER_SERVICE_TOKEN=$(cat $TOKEN_FILE)|" $FILE

# Check if the sed command was successful
if [ $? -eq 0 ]; then
  echo "The environment variable FLEET_SERVER_SERVICE_TOKEN was successfully updated in $FILE."
  
  # Remove the .bak file
  rm "${FILE}.bak"
else
  echo "Failed to update the environment variable FLEET_SERVER_SERVICE_TOKEN in $FILE."
fi