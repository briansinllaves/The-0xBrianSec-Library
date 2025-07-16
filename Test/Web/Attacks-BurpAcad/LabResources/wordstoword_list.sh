#!/bin/bash

# Check if a file path is provided as an argument
if [[ $# -eq 0 ]]; then
  echo "Please provide the path to the text file as an argument."
  exit 1
fi

# Read the file line by line and split words
while IFS= read -r line; do
  # Split line into words
  words=($line)

  # Loop through each word and print in a column
  for word in "${words[@]}"; do
    echo "$word"
  done
done < "$1"
