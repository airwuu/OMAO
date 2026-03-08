#!/bin/bash
sudo ip addr add 192.168.50.2/24 dev eth0
sudo ip link set eth0 up
sudo ip route add default via 192.168.50.1
echo "nameserver 1.1.1.1" | sudo tee /etc/resolv.conf
sudo nmcli device wifi hotspot ssid ubuntu1 password password1 ifname wlan0
