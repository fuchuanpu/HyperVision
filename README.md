# HyperVision
![Licence](https://img.shields.io/github/license/fuchuanpu/HyperVision)
![Last](https://img.shields.io/github/last-commit/fuchuanpu/HyperVision)
![Language](https://img.shields.io/github/languages/count/fuchuanpu/HyperVision)

A demo of the flow interaction graph based attack traffic detection system, i.e., HyperVision:

___Detecting Unknown Encrypted Malicious Traffic in Real Time via Flow Interaction Graph Analysis___  
In the $30^{th}$ Network and Distributed System Security Symposium ([NDSS'23](https://www.ndss-symposium.org/ndss-paper/detecting-unknown-encrypted-malicious-traffic-in-real-time-via-flow-interaction-graph-analysis/)).  
[Chuanpu Fu](https://www.fuchuanpu.cn), [Qi Li](https://sites.google.com/site/qili2012), and [Ke Xu](http://www.thucsnet.org/xuke.html).  


> The new CDN for the dataset has been successfully established. Please feel free to explore and utilize it! 🍺


## __0x00__ Hardware
- AWS EC2 c4.4xlarge, 100GB SSD, canonical `Ubuntu` 22.04 LTS (amd64, 3/3/2023).
- Tencent Cloud CVM, _with similar OS and hardware configurations_.

## __0x01__ Software
The demo can be built from a clean `Ubuntu` env.

```bash
# Establish env.
git clone https://github.com/fuchuanpu/HyperVision.git
cd HyperVision
sudo ./env/install_all.sh

# Download dataset.
wget https://www.hypervision.fuchuanpu.xyz/hypervision-dataset.tar.gz
tar -xxf hypervision-dataset.tar.gz
rm $_

# Build and run HyperVision.
./script/rebuild.sh
./script/expand.sh
cd build && ../script/run_all_brute.sh && cd ..

# Analyze the results.
cd ./result_analyze
./batch_analyzer.py -g brute
cat ./log/brute/*.log | grep AU_ROC
cd -
```

## __0x02__ Reference
``` bibtex
@inproceedings{NDSS23-HyperVision,
  author    = {Chuanpu Fu and
               others},
  title     = {Detecting Unknown Encrypted Malicious Traffic in Real Time via Flow 
               Interaction Graph Analysis},
  booktitle = {NDSS},
  publisher = {ISOC},
  year      = {2023}
}
```
