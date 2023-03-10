#!/usr/bin/env bash

set -eux

BASE_NAME=$(basename $(pwd))

if [ $BASE_NAME != "HyperVision" ] && [ $BASE_NAME != "hypervision" ]; then
    echo "This script should be executed in the root dir of HyperVision."
    exit -1
fi

chmod +x ./script/*.sh

./script/run_expand.sh
./env/install_all.sh
./script/run_rebuild.sh

echo "Done."
