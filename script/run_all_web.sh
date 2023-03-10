#!/usr/bin/env bash

set -eux

ninja


ARR=(
    "agentinject"
    "codeinject"
    "csfr"
    "oracle"
    "paraminject"
    "persistence"
    "scrapy"
    "sslscan"
    "webshell"
    "xss"
)

for item in ${ARR[@]}; do
    ./HyperVision -config ../configuration/web/${item}.json > ../cache/${item}.log &
done
