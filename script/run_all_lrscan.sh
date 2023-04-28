#!/usr/bin/env bash

set -eux

ninja


ARR=(
    "dns_lrscan"
    "http_lrscan"
    "icmp_lrscan"
    "netbios_lrscan"
    "rdp_lrscan"
    "smtp_lrscan"
    "snmp_lrscan"
    "ssh_lrscan"
    "telnet_lrscan"
    "vlc_lrscan"
)

for item in ${ARR[@]}; do
    ./HyperVision -config ../configuration/lrscan/${item}.json > ../cache/${item}.log # &
done
