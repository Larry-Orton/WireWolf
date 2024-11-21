#!/bin/bash

echo "Setting up WireWolf..."

# Update the package index
sudo apt update

# Install system-wide dependencies
echo "Installing required system packages..."
sudo apt install -y python3 python3-pip python3-nmap python3-requests nmap

# Install remaining Python dependencies
echo "Installing Python packages..."
pip3 install geoip2 ipwhois --user

# Install the tool
echo "Installing WireWolf..."
sudo pip3 install .

echo "Setup complete! You can now run the tool with 'wirewolf -t <target>'"
