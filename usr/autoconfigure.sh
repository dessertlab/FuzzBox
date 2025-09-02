#!/bin/bash

if [ $# -eq 0 ]; then
  echo "Usage: $0 <python file>"
  exit 1
fi

conf_file=$1

# Check if the directory exists
if [ ! -f "$conf_file" ]; then
    echo "Error: File $conf_file does not exist."
    exit 1
fi

sudo setxkbmap us
sudo python3 $conf_file
sudo setxkbmap it
