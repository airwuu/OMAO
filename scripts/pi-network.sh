#!/bin/bash

# Ensure the script is run as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root. Try: sudo ./setup_pi_network.sh"
   exit 1
fi

# Variables (Change 'eth0' if your Pi uses a different interface name like 'end0')
INTERFACE="eth0"
PI_IP="192.168.50.2/24"
GATEWAY_IP="192.168.50.1"
DNS_SERVER="8.8.8.8"

echo "Configuring Raspberry Pi network on $INTERFACE..."

# Step 1: Clear old IPs and bring the interface up
echo "Flushing old IP settings on $INTERFACE..."
ip addr flush dev $INTERFACE
ip link set $INTERFACE up

# Step 2: Assign the static IP
echo "Assigning static IP: $PI_IP..."
ip addr add $PI_IP dev $INTERFACE

# Step 3: Set the default gateway
echo "Setting default gateway to: $GATEWAY_IP..."
ip route add default via $GATEWAY_IP dev $INTERFACE

# Step 4: Configure DNS
echo "Setting DNS server to: $DNS_SERVER..."
echo "nameserver $DNS_SERVER" > /etc/resolv.conf

echo "-----------------------------------"
echo "Network configuration complete!"
echo "Pinging the internet to test..."
ping -c 4 $DNS_SERVER
