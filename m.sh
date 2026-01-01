#!/bin/bash
set -e

echo "Updating system..."
apt update

echo "Installing Python, pip, venv, and screen..."
apt-get install -y python3 python3-pip python3-venv screen

echo "Creating virtual environment..."
python3 -m venv venv

echo "Activating venv..."
source venv/bin/activate

echo "Upgrading pip..."
pip install --upgrade pip

echo "Installing Python packages..."
pip install requests

echo "Stopping old screen session if exists..."
screen -S venom -X quit || true

echo "Starting m.py in screen session: venom"
screen -dmS venom bash -c "source venv/bin/activate && python m.py"

echo "Screen session 'venom' started"
