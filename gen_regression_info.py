#!/usr/bin/env python3
"""
gen_regression_info.py 
Author: Gerry Wan

"""

import argparse
import json
import pickle
import relays
from scipy import stats 

ip_to_as = json.load(open("guard_info/ip_to_as.json"))  
guard_to_bw = pickle.load(open("guard_info/guard_to_bw.pickle", "rb"))
guard_fp_to_bw = {g.fingerprint: bw for (g, bw) in guard_to_bw.items()}

def parse_args():
    parser = argparse.ArgumentParser()
    return parser.parse_args()

def get_guard_to_real(ns_filename):
    """
    Returns a dict mapping guard fingerprint to *observed*
    bandwidth (in Bytes/second)
    """

    ns = relays.tempest_fat_network_state(ns_filename)
    cons_rel_stats = ns.cons_rel_stats
    descriptors = ns.descriptors

    fp_to_real = {}
    for fp, relay in descriptors.items():
        fp_to_real[fp] = min(relay.average_bandwidth, relay.observed_bandwidth)

    guard_fp_to_real = {fp: fp_to_real[fp] for fp in guard_fp_to_bw}

    return guard_fp_to_real


def get_lin_reg(guard_fp_to_bw, guard_fp_to_real):
    """
    Prints linear regression between bandwidth weights of guards
    and real bandwidth (B/s) 
    """
    # remove 0 bw weight guards
    fp_to_bw = {}
    for fp, bw in guard_fp_to_bw.items():
        if bw != 0:
            fp_to_bw[fp] = bw

    fp_to_real = {fp: guard_fp_to_real[fp] for fp in fp_to_bw}

    bw_weights = list(fp_to_bw.values())
    bw_real = list(fp_to_real.values())

    x = bw_weights
    y = bw_real
    slope, intercept, r_value, p_value, std_err = stats.linregress(x,y)
    print("=== weights on x axis ===")
    print(f'slope: {slope}')
    print(f'intercept: {intercept}')
    print(f'r squared: {r_value**2}')

    slope, intercept, r_value, p_value, std_err = stats.linregress(y,x)
    print("=== weights on y axis ===")
    print(f'slope: {slope}')
    print(f'intercept: {intercept}')
    print(f'r squared: {r_value**2}')


def main(args):
    ns_filename = "data/2018-08-01-07-00-00-network_state"
    guard_fp_to_real = get_guard_to_real(ns_filename)
    get_lin_reg(guard_fp_to_bw, guard_fp_to_real)

if __name__ == "__main__":
    main(parse_args())
