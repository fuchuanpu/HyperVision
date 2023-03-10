#!/usr/bin/env bash

set -eux

DIR_NAMES=(
    "cache"
    "temp"
    "data"
)
readonly DIR_NAMES TARGETS

function test_and_create() {
    if [ $# != 1 ]; then
        echo "Invalid arguments."
        return -1;
    fi
    if [ ! -d "$1" ]; then
        mkdir "$1"
    fi
}

BASE_NAME=$(basename $(pwd))

if [ $BASE_NAME != "HyperVision" ] && [ $BASE_NAME != "hypervision" ]; then
    echo "This script should be executed in the root dir of HyperVision."
    exit -1
fi

echo "Create directories."

for dir_name in ${DIR_NAMES[@]}; do
    test_and_create ./${dir_name}
done
