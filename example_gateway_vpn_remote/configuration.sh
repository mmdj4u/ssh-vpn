#!/bin/bash
# This is a sourced config file

# Tunnel DNS queries also. This is for when you want the VPN to deeply protect your traffic from the
# local network. 1 = protect my DNS traffic, 0 = use local DNS
# Note that using local DNS can be considered a security risk.
TUNNEL_DNS=1

# DNS servers
# Will be used if and only if TUNNEL_DNS=1
# This is a space separated list of addresses
DNS_SERVERS="8.8.8.8 8.8.4.4"

# Search domain
# Will be used if and only if TUNNEL_DNS=1
# This will be a fully qualified domain name for the domain to be used in host search queries or
# null if no search domain is required.
# Example 1 (we'll search example.com for host resolution):
#   DNS_SEARCH="example.com"
# Example 2 (no search domain required):
#   DNS_SEARCH=
DNS_SEARCH=

# Status: ping host
# This host will get ping'd when checking the status of the VPN using:
# ssh-vpn.sh status
# The value must be a FQDN, IP address, or null. If null, then we'll attempt to automatically detect
# the nexthop past the remote host's default gateway and use that to determine the status of this
# VPN implementation (see REMOTE_HOP_COUNT_TO_EGRESS below).
#
PING_HOST=
