#!/usr/bin/env bash

set -eux

BASE_NAME=$(basename $(pwd))

if [ $BASE_NAME != "HyperVision" ] && [ $BASE_NAME != "hypervision" ]; then
    echo "This script should be executed in the root dir of HyperVision."
    exit -1
fi


function clean_dir () {
    if [ $# != 2 ]; then
        echo "Invalid arguments."
        return -1;
    fi

    if [ -d "./$1" ]; then
        cd "./$1"
        TARGET_CTR=$(ls -al | grep .$2 | wc -l)
        if (( $((TARGET_CTR)) > 0 )); then
            rm *.$2
        fi
        cd -
    fi
    return 0;
}

clean_dir "temp" "txt"
clean_dir "cache" "log"

if [ -d ./result_analyze/log ]; then
    rm -r ./result_analyze/log
fi

if [ -d ./result_analyze/figure ]; then
    rm -r ./result_analyze/figure
fi

if [ -d ./build ]; then
    cd build && ninja clean && cd ..
fi
