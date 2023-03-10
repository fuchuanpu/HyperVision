#!/usr/bin/env bash

set -eux

ninja


ARR=(
    "sshpwdsm"
    "sshpwdmd"
    "sshpwdla"
    "telnetpwdsm"
    "telnetpwdmd"
    "telnetpwdla"
    "spam1"
    "spam50"
    "spam100"
    "crossfiresm"
    "crossfiremd"
    "crossfirela"
    "lrtcpdos02"
    "lrtcpdos05"
    "lrtcpdos10"
    "ackport"
    "ipidaddr"
    "ipidport"
)

for item in ${ARR[@]}; do
    ./HyperVision -config ../configuration/misc/${item}.json > ../cache/${item}.log &
done
