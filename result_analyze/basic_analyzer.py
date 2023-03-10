#!/usr/bin/env python3

import json
from threading import local
import time
import os
import math
import argparse

from numpy import void
from common import *
from typing import List, Tuple
import matplotlib.pyplot as plt
from sklearn.metrics import roc_curve, auc, accuracy_score,\
    f1_score, precision_score, recall_score, precision_recall_curve, fbeta_score


@time_log
@call_log(f"Calculate ROC related metrics.")
def roc_action(label: List[int], score: List[float]) -> void:
    fpr, tpr, _ = roc_curve(label, score)
    roc_auc = auc(fpr, tpr)

    plt.figure()
    plt.plot(fpr, tpr, color='firebrick',
             lw=1.5, label=f'AUC: {roc_auc:7.6f}')
    plt.plot([0, 1], [0, 1], color='royalblue', lw=1, linestyle='--')
    plt.xlim([-0.02, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title(f'{args.target} RoC')
    plt.legend(loc="lower right")

    if not os.path.exists(f"./figure/"):
        os.mkdir(f"./figure/")
    if not os.path.exists(f"./figure/{class_name}"):
        os.mkdir(f"./figure/{class_name}/")

    plt.savefig(f"./figure/{class_name}/{args.target}_ROC.png")

    deta = 1
    deta_fpr = 1
    deta_tpr = 1

    err = 0
    r_fpr = 0
    r_tpr = 0
    for a, b in zip(fpr, tpr):
        d = math.fabs((1 - a) - b)
        if d < deta:
            deta = d
            err = a

        d = math.fabs(a - 0.1)
        if d < deta_fpr:
            deta_fpr = d
            r_tpr = b

        d = math.fabs(b - 0.9)
        if d < deta_tpr:
            deta_tpr = d
            r_fpr = a

    print(f"[{class_name}-{args.target}]")
    print(f"TPR={r_tpr:7.6f} (FPR=0.1)")
    print(f"FPR={r_fpr:7.6f} (TPR=0.9)")
    print(f"AU_ROC={roc_auc:7.6f}")
    print(f"EER={err:7.6f}")


@time_log
@call_log(f"Calculate PRC related metrics.")
def f_action(label: List[int], score: List[float]) -> void:
    judge = [1 if sc > water_line else 0 for sc in score]

    f1 = f1_score(label, judge, average='macro')
    pre = precision_score(label, judge, average='macro')
    rec = recall_score(label, judge, average='macro')
    acc = accuracy_score(label, judge)
    f2 = fbeta_score(label, judge, average='macro', beta=2)
    fpr, tpr, thresholds = roc_curve(label, judge)

    p, r, _ = precision_recall_curve(label, judge)
    pr_auc = auc(p, r)

    plt.figure()
    plt.plot(p, r, color='firebrick',
             lw=1.5, label=f'AUC: {pr_auc:7.6f}')
    plt.plot([0, 1], [0, 1], color='royalblue', lw=1, linestyle='--')
    plt.xlim([-0.02, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('Precision')
    plt.ylabel('Recall')
    plt.title(f'{args.target} RoC')
    plt.legend(loc="lower right")

    if not os.path.exists(f"./figure/"):
        os.mkdir(f"./figure/")
    if not os.path.exists(f"./figure/{class_name}"):
        os.mkdir(f"./figure/{class_name}/")

    plt.savefig(f"./figure/{class_name}/{args.target}_PRC.png")

    print(f'F1-score={f1:7.6f}')
    print(f'F2-score={f2:7.6f}')
    print(f'Precision={pre:7.6f}')
    print(f'Recall={rec:7.6f}')
    print(f'AU_PRC={pr_auc:7.6f}')
    print(f'Accuracy={acc:7.6f}')
    assert(len(fpr) == 3)
    assert(len(tpr) == 3)
    print(f'TPR={tpr[1]:7.6f}')
    print(f'FPR={fpr[1]:7.6f}')

    n_FP = 0
    n_FN = 0
    for a, b in zip(label, judge):
        if a == 1 and b == 0:
            n_FN += 1
        if a == 0 and b == 1:
            n_FP += 1
    print(f'FN={n_FN}')
    print(f'FP={n_FP}')


@time_log
@call_log(f"Start analyze results.")
def analyze_result(label: List[int], score: List[float]) -> bool:
    roc_action(label, score)
    f_action(label, score)
    return True


@time_log
@call_log(f"Read result file.")
def get_resulf_from_file(addr: str) -> Tuple[List[int], List[float]]:
    label = []
    score = []
    for line in open(addr):
        _ve = line.split()
        label.append(int(_ve[0]))
        score.append(float(_ve[1]))
    return label, score


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument('-c', '--config', type=str, default='configure.json', help='Location of configuration.')
    parser.add_argument('-t', '--target', type=str, default='synsdos', help='Target for analysis.')

    args = parser.parse_args()

    if not os.path.exists(args.config):
        logging.fatal(f"Configuration {args.config} not exists.")
        exit(-1)

    with open(args.config, 'r') as f:
        configd = json.load(f)
        for k,v in configd.items():
            if args.target in v:
                water_line = v[args.target]
                class_name = k
                break

    if 'water_line' not in locals():
        logging.fatal(f"The dataset {args.target} not exists.")
        exit(-1)

    analyze_result(*get_resulf_from_file(f"../temp/{args.target}.txt"))
