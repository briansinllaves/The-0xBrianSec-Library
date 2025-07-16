#!/bin/bash
# Converting a JSON file to a bash variable using jq
json_data=$(cat data.json)
echo "JSON data: $json_data"

# Parsing JSON (assuming jq is installed)
echo "$json_data" | jq '.key'
