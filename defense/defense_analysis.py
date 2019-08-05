#!/usr/bin/env python3
"""
defense_analysis.py
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
import defense_framework as df

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
    parser.add_argument('--dump', action='store_true')
    return parser.parse_args()

# --------------------------------------------------------------

def counterraptor_init_ratios(client_as, fp_to_bw, fp_to_as, fp_to_cost):
    """
    Returns selection probability to cost ratio for client_as
    before applying redistribution algorithm to Counter-RAPTOR.
    """

    client_to_all_res = json.load(open("../counterraptor/all_reachable_resilience.json"))
    client_to_guard_res = json.load(open("../counterraptor/cg_resilience.json"))
    alpha = 0.5
    sample_size = 0.1*len(fp_to_bw)

    total_cost = sum(fp_to_cost.values())

    ratios = dict.fromkeys(fp_to_bw, 0)
    distr = counterraptor.compute_cr_selection_probs(client_as,
                                fp_to_bw,
                                fp_to_as,
                                client_to_all_res,
                                client_to_guard_res,
                                alpha,
                                sample_size)

    for fp, prob in distr.items():
        cost = relays.get_cost(fp_to_bw[fp])
        ratio = prob * total_cost / cost
        ratios[fp] = ratio

    return ratios

def denasa_init_ratios(client_as, fp_to_bw, fp_to_as, fp_to_cost):
    """
    Returns selection probability to cost ratio for client_as
    before applying redistribution algorithm to DeNASA.
    """

    total_cost = sum(fp_to_cost.values())

    ratios = dict.fromkeys(fp_to_bw, 0)
    distr = denasa.compute_dn_selection_probs(client_as,
                                                fp_to_bw,
                                                fp_to_as, 
                                                all_ases, 
                                                pfi_instance)

    for fp, prob in distr.items():
        cost = relays.get_cost(fp_to_bw[fp])
        ratio = prob * total_cost / cost
        ratios[fp] = ratio

    return ratios


def lastor_init_ratios(client_coord, fp_to_bw, fp_to_coord, fp_to_cost):
    """
    Returns selection probability to cost ratio for client_coord
    before applying redistribution algorithm to LASTor.
    """

    total_cost = sum(fp_to_cost.values())

    ratios = dict.fromkeys(fp_to_bw, 0)
    distr = lastor.compute_lt_selection_probs(client_coord,
                                              fp_to_coord)

    for fp, prob in distr.items():
        cost = relays.get_cost(fp_to_bw[fp])
        ratio = prob * total_cost / cost
        ratios[fp] = ratio

    return ratios

# --------------------------------------------------------------

def client_to_init_ratios_cr(client_as_lst, dump):
    """
    Dumps Counter-RAPTOR probability to cost ratios 
    for all clients in client_as_lst.
    """
    print("Counter-RAPTOR")

    all_ratios = np.array([])
    client_to_ratios = {}

    for client_as in client_as_lst:
        ratios = counterraptor_init_ratios(client_as, fp_to_bw, fp_to_as, fp_to_cost)
        all_ratios = np.append(all_ratios, list(ratios.values()))
        client_to_ratios[client_as] = list(ratios.values())

    if dump:
        json.dump(client_to_ratios, open("init_ratios_cr.json", "w"))

    return client_to_ratios


def client_to_init_ratios_dn(client_as_lst, dump):
    """
    Dumps DeNASA probability to cost ratios 
    for all clients in client_as_lst.
    """

    print("DeNASA")

    all_ratios = np.array([])
    client_to_ratios = {}

    for client_as in client_as_lst:
        ratios = denasa_init_ratios(client_as, fp_to_bw, fp_to_as, fp_to_cost)
        all_ratios = np.append(all_ratios, list(ratios.values()))
        client_to_ratios[client_as] = list(ratios.values())

    if dump:
        json.dump(client_to_ratios, open("init_ratios_dn.json", "w"))

    return client_to_ratios


def client_to_init_ratios_lt(client_coord_lst, dump):
    """
    Dumps LASTor probability to cost ratios 
    for all clients in client_coord_lst.
    """

    print("LASTor")

    all_ratios = np.array([])
    client_to_ratios = {}

    for client_coord in client_coord_lst:
        ratios = lastor_init_ratios(client_coord, fp_to_bw, fp_to_coord, fp_to_cost)
        all_ratios = np.append(all_ratios, list(ratios.values()))
        client_to_ratios[str(client_coord)] = list(ratios.values())

    if dump:
        json.dump(client_to_ratios, open("init_ratios_lt.json", "w"))

    return client_to_ratios


# --------------------------------------------------------------


def get_client_aggr_resilient(client_as_lst, thresholds, dump):
    """
    Returns a dict mapping thresholds to dict of client AS to 
    aggregated probability of the client choosing a suspect-free guard.
    (Counter-RAPTOR)
    """

    client_to_guard_res = json.load(open('../counterraptor/cg_resilience.json'))

    aggr_cr = {}
    for threshold in thresholds:

        client_to_aggr_resilient = {}
        for client_as in client_as_lst:
            print(f'thresh: {threshold}')
            resiliences = client_to_guard_res[client_as]
            redistr = df.counterraptor_redistr(client_as, 
                                                fp_to_bw, 
                                                fp_to_as,
                                                threshold)

            aggr_prob = 0
            for fp, prob in redistr.items():
                res = resiliences[fp_to_as[fp]]
                aggr_prob += (prob * res)

            client_to_aggr_resilient[client_as] = min(aggr_prob, 1)
        aggr_cr[threshold] = client_to_aggr_resilient

    if dump:
        json.dump(aggr_cr, open("aggr_cr.json", "w"))

    return aggr_cr


def get_client_aggr_suspectfree(client_as_lst, thresholds, dump):
    """
    Returns a dict mapping thresholds to dict of client AS to 
    aggregated probability of the client choosing a suspect-free guard.
    (DeNASA)
    """

    client_to_guard_usability = json.load(open('../denasa/client_to_guard_usability.json'))

    aggr_dn = {}
    for threshold in thresholds:

        client_to_aggr_suspectfree = {}
        for client_as in client_as_lst:

            usability = client_to_guard_usability[client_as]
            redistr = df.denasa_redistr(client_as, 
                                        fp_to_bw, 
                                        fp_to_as, 
                                        threshold)

            aggr_prob = 0
            for fp, prob in redistr.items():
                if usability[fp]:
                    # if guard is suspect-free
                    aggr_prob += prob

            client_to_aggr_suspectfree[client_as] = min(aggr_prob, 1)
        aggr_dn[threshold] = client_to_aggr_suspectfree

    if dump:
        json.dump(aggr_dn, open("aggr_dn.json", "w"))

    return aggr_dn

def get_client_aggr_distance(client_coord_lst, thresholds, dump):
    """
    Returns a dict mapping thresholds to dict of client coord to 
    normalized distance of the client choosing a guard.
    (LASTor)
    """

    client_to_guard_dist = json.load(open('../lastor/client_to_guard_dist_200.json'))

    aggr_lt = {}
    for threshold in thresholds:

        client_to_aggr_dist = {}
        for client_coord in client_coord_lst:
            print(f'thresh: {threshold}')

            distances = client_to_guard_dist[str(tuple(client_coord))]

            redistr = df.lastor_redistr(client_coord,
                                        fp_to_bw,
                                        fp_to_coord,
                                        threshold)

            aggr_dist = 0
            for fp, prob in redistr.items():
                if fp in distances:
                    # if fp not in distances, prob is 0 anyway
                    aggr_dist += (prob * distances[fp])


            client_to_aggr_dist[str(tuple(client_coord))] = aggr_dist

        aggr_lt[threshold] = client_to_aggr_dist

    if dump:
        json.dump(aggr_lt, open("aggr_lt.json", "w"))

    return aggr_lt




def main(args):
    dump = args.dump

    client_as_lst = [asn.strip() for asn in open("../data/top368client.txt", 'r').readlines()]
    client_coord_lst = json.load(open('../data/geoclients200.json', 'r'))

    thresholds = [1, 1.1, 1.25, 1.5, 2000]
    get_client_aggr_resilient(client_as_lst, thresholds, dump)

    thresholds = [1, 1.25, 1.5, 2, 10, 2000]
    get_client_aggr_suspectfree(client_as_lst, thresholds, dump)

    thresholds = [1, 2, 5, 10, 20, 2000]
    get_client_aggr_distance(client_coord_lst, thresholds, dump)


    client_to_init_ratios_cr(client_as_lst, dump)
    client_to_init_ratios_dn(client_as_lst, dump)
    client_to_init_ratios_lt(client_coord_lst, dump)


if __name__ == "__main__":
    main(parse_args())