#!/usr/bin/env python3

import json
import time
import os
import argparse
from common import *
import multiprocessing as mp


def analyze_thread_template(task:str) -> None:
    logging.info(f"Start to analyze {task}")
    if not os.path.exists(f'./log/{args.group}'):
        os.mkdir(f"./log/{args.group}")

    os.system(f"./basic_analyzer.py -t {task}" + 
              f" > ./log/{args.group}/{task}.log")


@time_log
@call_log("Start bacth analyzing.")
def analyze_group() -> None:
    pl = []
    for ts in task_list:
        pl.append(mp.Process(target=analyze_thread_template, args=(ts,)))
    
    [p.start() for p in pl]
    [p.join() for p in pl]


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument('-c', '--config', type=str, default='configure.json', help='Location of configuration.')
    parser.add_argument('-g', '--group', type=str, default='brute', help='Group for analysis.')

    args = parser.parse_args()

    if not os.path.exists("./figure/"):
        os.mkdir("./figure/")

    if not os.path.exists("./log/"):
        os.mkdir("./log/")

    if not os.path.exists(args.config):
        logging.fatal(f"Configuration {args.config} not exists.")
        exit(-1)

    with open(args.config, 'r') as f:
        configd = json.load(f)
        if args.group not in configd:
            logging.fatal(f"Group {args.group} not found.")
        task_list = list(configd[args.group].keys())

    analyze_group()
