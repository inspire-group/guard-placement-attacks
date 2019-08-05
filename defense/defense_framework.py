#!/usr/bin/env python3
"""
defense_framework.py
Author: Gerry Wan

Functions for performing guard placement defense analysis.
"""

import sys

sys.path.append('..')
sys.path.append('../vanilla')
sys.path.append('../denasa')
sys.path.append('../counterraptor')
sys.path.append('../lastor')

import vanilla
import denasa
import counterraptor
import lastor

import numpy as np
import argparse
import pfi
import json
import pickle
import copy
import relays
import matplotlib.pyplot as plt

# initialize vars
paths_filename = "as_paths.txt"
index_filename = "as_paths_index.bin"
libspookyhash_filename = "../denasa/libspookyhash.so"

pfi_instance = pfi.PFI(libspookyhash_filename,
                paths_filename,
                index_filename)

pfi_instance.load()
pfi_instance.verify()

ip_to_as = json.load(open("../guard_info/ip_to_as.json"))
all_ases = [asn.strip() for asn in open("../data/relay_ases.txt", 'r').readlines()]

guard_to_bw = pickle.load(open("../guard_info/guard_to_bw.pickle", "rb"))

fp_to_bw = {g.fingerprint: bw for (g, bw) in guard_to_bw.items()}
fp_to_as = {g.fingerprint: ip_to_as[g.address] for (g, bw) in guard_to_bw.items()}
fp_to_coord = pickle.load(open("../guard_info/guard_fps_to_coord.pickle", "rb"))
fp_to_cost = {fp: relays.get_cost(bw) for fp, bw in fp_to_bw.items()}


def parse_args():
    parser = argparse.ArgumentParser()
    return parser.parse_args()
    

def counterraptor_redistr(client_as, fp_to_bw, fp_to_as, threshold):
    """
    Redistributes Counter-RAPTOR guard probabilities.
    threshold = selection probability to fraction of the cost of the network
                contributed
    """

    if threshold < 1:
        print("Error: threshold must be at least 1.")
        return None

    client_to_all_res = json.load(open("../counterraptor/all_reachable_resilience.json"))
    client_to_guard_res = json.load(open("../counterraptor/cg_resilience.json"))
    alpha = 0.5
    sample_g = 0.1
   
    total_cost = 0
    for fp, bw in fp_to_bw.items():
        total_cost += relays.get_cost(bw)
    
    thresh = threshold / total_cost

    ratios = dict.fromkeys(fp_to_bw, 0)
    excess = 1

    curr_fps = list(fp_to_bw.keys())
    cnt = 1
    while excess > 0:
        print(f'----- Round {cnt} -----')
        cnt += 1
        
        if len(curr_fps) == 0:
            break
       
        curr_fp_to_bw = {fp: fp_to_bw[fp] for fp in curr_fps}
        curr_fp_to_as = {fp: fp_to_as[fp] for fp in curr_fps}
        curr_distr = counterraptor.compute_cr_selection_probs(client_as,
                                curr_fp_to_bw,
                                curr_fp_to_as,
                                client_to_all_res,
                                client_to_guard_res,
                                alpha,
                                sample_g * len(curr_fp_to_bw))
        print(f'sum distr (~1): {sum(curr_distr.values())}')

        norm = excess
        print(f'norm: {norm}')

        num_over = 0
        excess = 0
        for fp in list(curr_fps):
            cost = relays.get_cost(fp_to_bw[fp])
            ratio = curr_distr[fp] / cost * norm
            ratios[fp] += ratio

            if ratios[fp] > thresh:
                excess += ((ratios[fp] - thresh) * cost)
                ratios[fp] = thresh
                curr_fps.remove(fp)

                num_over += 1

        print(f'num over thresh: {num_over}')

    redistr = {}
    for fp, val in ratios.items():
        prob = val * relays.get_cost(fp_to_bw[fp])
        redistr[fp] = prob

    return redistr


def denasa_redistr(client_as, fp_to_bw, fp_to_as, threshold):
    """
    Redistributes DeNASA guard probabilities.
    threshold = selection probability to fraction of the cost of the network
                contributed
    """
    
    if threshold < 1:
        print("Error: threshold must be at least 1.")
        return None

    total_cost = 0
    for fp, bw in fp_to_bw.items():
        total_cost += relays.get_cost(bw)
    
    thresh = threshold / total_cost

    ratios = dict.fromkeys(fp_to_bw, 0)
    excess = 1

    curr_fps = list(fp_to_bw.keys())
    cnt = 1
    while excess > 0:
        print(f'----- Round {cnt} -----')
        cnt += 1
        
        if len(curr_fps) == 0:
            break
       
        curr_fp_to_bw = {fp: fp_to_bw[fp] for fp in curr_fps}
        curr_fp_to_as = {fp: fp_to_as[fp] for fp in curr_fps}
        curr_distr = denasa.compute_dn_selection_probs(client_as,
                                                        curr_fp_to_bw,
                                                        curr_fp_to_as, 
                                                        all_ases, 
                                                        pfi_instance)
        print(f'sum distr (~1): {sum(curr_distr.values())}')

        norm = excess
        print(f'norm: {norm}')

        num_over = 0
        excess = 0
        for fp in list(curr_fps):
            cost = relays.get_cost(fp_to_bw[fp])
            ratio = curr_distr[fp] / cost * norm
            ratios[fp] += ratio

            if ratios[fp] > thresh:
                excess += ((ratios[fp] - thresh) * cost)
                ratios[fp] = thresh
                curr_fps.remove(fp)

                num_over += 1

        print(f'num over thresh: {num_over}')

    redistr = {}
    for fp, val in ratios.items():
        prob = val * relays.get_cost(fp_to_bw[fp])
        redistr[fp] = prob

    return redistr


def lastor_redistr(client_coord, fp_to_bw, fp_to_coord, threshold):
    """
    Redistributes LASTor guard probabilities.
    threshold = selection probability to fraction of the cost of the network
                contributed
    """

    if threshold < 1:
        print("Error: threshold must be at least 1.")
        return None

    total_cost = 0
    for fp, bw in fp_to_bw.items():
        total_cost += relays.get_cost(bw)
    
    thresh = threshold / total_cost

    ratios = dict.fromkeys(fp_to_bw, 0)
    excess = 1

    curr_fps = list(fp_to_coord.keys())
    cnt = 1
    while excess > 0:
        print(f'----- Round {cnt} -----')
        cnt += 1
        
        if len(curr_fps) == 0:
            break
        
        curr_fp_to_coord = {fp: fp_to_coord[fp] for fp in curr_fps}
        curr_distr = lastor.compute_lt_selection_probs(client_coord,
                                                       curr_fp_to_coord)
        print(f'sum distr (~1): {sum(curr_distr.values())}')

        norm = excess
        print(f'norm: {norm}')

        num_over = 0
        excess = 0
        for fp in list(curr_fps):
            cost = relays.get_cost(fp_to_bw[fp])
            ratio = curr_distr[fp] / cost * norm
            ratios[fp] += ratio

            if ratios[fp] > thresh:
                excess += ((ratios[fp] - thresh) * cost)
                ratios[fp] = thresh
                curr_fps.remove(fp)

                num_over += 1

        print(f'num over thresh: {num_over}')

    redistr = {}
    for fp, val in ratios.items():
        prob = val * relays.get_cost(fp_to_bw[fp])
        redistr[fp] = prob

    return redistr


def main(args):
    pass

if __name__ == "__main__":
    main(parse_args())