# guard-placement-attacks

This repository contains code used in 

__Guard Placement Attacks on Path Selection Algorithms for Tor__
Gerry Wan, Aaron Johnson, Ryan Wails, Sameer Wagh, Prateek Mittal
Proceedings on Privacy Enhancing Technologies (PoPETs), 2019
[https://petsymposium.org/2019/files/papers/issue4/popets-2019-0069.pdf]

### Usage
Download a recent Tor consensus file and server descriptors from [CollecTor](https://metrics.torproject.org/collector.html), AS relationship data from [CAIDA](http://data.caida.org/datasets/as-relationships/), and IP to geolocation database from [MaxMind](https://dev.maxmind.com/geoip/geoip2/geolite2/).

Generate a network state file using by running `process_consensus.py`.

Run `gen_relay_info.py` to generate guard and relay information. 

Code for analyzing Counter-RAPTOR, DeNASA, and LASTor are in their respective directories, as is the implementation and analysis of the defense algorithm.