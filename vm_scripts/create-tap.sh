#!/bin/sh
# Sets up the `puff-tap` host interface (192.168.8.1/24) used by `run-linux.sh`.
# For Motor OS's `moto-tap` interface (192.168.4.1/24), run:
#   ../../motor-dev/motor-os/vm_images/release/create-tap.sh
# (see https://github.com/moturus/motor-os/blob/main/docs/build.md).

sudo ip tuntap add mode tap puff-tap
sudo ip addr add 192.168.8.1/24 dev puff-tap
sudo ip addr add 2001:de8::1/64 dev puff-tap
sudo ip link set puff-tap up

# Enable IPv4 forwarding on the host
sudo sysctl -w net.ipv4.ip_forward=1

# 1. Create a NAT table for IPv4
sudo nft add table ip nat

# 2. Create a postrouting chain for source NAT (masquerading)
sudo nft add chain ip nat postrouting '{ type nat hook postrouting priority 100; policy accept; }'

# 3. Add a rule to masquerade traffic coming from the VM's subnet
sudo nft add rule ip nat postrouting ip saddr 192.168.8.0/24 masquerade
