#!/bin/bash

# Run this script in sudo.

if [[ "$OSTYPE" != "linux-gnu"* ]];
  echo "Run this script on Linux"
  exit 1
fi

brctl addbr br0
ip addr add 192.168.179.1/24 broadcast 192.168.179.255 dev br0
ip link set br0 up

ip tuntap add dev tap0 mode tap
ip link set tap0 up promisc on

brctl addif br0 tap0

dnsmasq --interface=br0 --bind-interfaces --dhcp-range=192.168.179.10,192.168.179.254
