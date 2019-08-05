#!/usr/bin/env python3
"""
selection_analysis_LT.py
Author: Gerry Wan

Functions for performing selection probability analysis in LASTor.
"""

import sys

sys.path.append('..')
sys.path.append('../vanilla')

import numpy as np
import argparse
import lastor as lt
import vanilla
import relays
import json
import pickle
import operator
import geopy.distance


guard_to_bw = pickle.load(open("../guard_info/guard_to_bw.pickle", "rb"))
guard_to_cost = {guard: relays.get_cost(bw) for guard, bw in guard_to_bw.items()}
relay_ips = [ip.strip() for ip in open('../data/relay_ips.txt', 'r').readlines()]

def make_prob_matrix(client_lst, mal_coord, bw_resources_lst):
    """
    Returns a numpy matrix where every row corresponds to the bandwidth

    col_0: Vanilla Tor selection probability
    col_1: Untargeted LT average selection probability (across all clients)
    col_2: Untargeted LT lowest selection probability
    col_3: Untargeted LT highest selection probability

    client_lst: client coordinates
    mal_coord:  malicious guard placement (single relay)
    bw_resources_lst: list of bandwidth resources
    """

    prob_matrix = np.zeros(shape=(len(bw_resources_lst), 4))
    for i in range(0, len(bw_resources_lst)):
        bw_resource = bw_resources_lst[i]
        print(f"Bandwidth: {bw_resource}")

        # ----------- Vanilla -----------

        v_guard_probs, v_prob = vanilla.compute_vanilla_guard_distr(guard_to_bw, bw_resource)
        prob_matrix[i][0] = v_prob

        # ------------ Untargeted LT ----------

        res = untargeted_prob(client_lst, [mal_coord], bw_resource)

        prob_matrix[i][1] = res[0]
        prob_matrix[i][2] = res[1][1]
        prob_matrix[i][3] = res[2][1]

        print(f"average prob: {res[0]}")
        print(f"lo client untargeted prob: {res[1][0]}, {res[1][1]}")
        print(f"hi client untargeted prob: {res[2][0]}, {res[2][1]}")        

    return prob_matrix


def untargeted_prob(client_lst, mal_coords_lst, bw_resource):
    """
    Computes selection untargeted attack success probability, given
    list of malicious guard placement locations.
    *Does not compute optimal guard placement locations.*

    client_lst:     list of client coordinates
    mal_coords_lst: list of malicious guard coordinates
    bw_resource:    total bandwidth endowment
    """
    g = 0.2
    # initial state of guards
    fp_to_coord = pickle.load(open("../guard_info/guard_fps_to_coord.pickle", "rb"))
    cluster_to_fp = lt.cluster(fp_to_coord)

    # convert guard_to_bw to fp_to_bw
    fp_to_bw = {}
    for guard, bw in guard_to_bw.items():
        fp_to_bw[guard.fingerprint] = bw

    mal_guard_bw = bw_resource / len(mal_coords_lst)

    mal_fps_to_coord = {}
    mal_fps_to_cluster = {}
    for i in range(len(mal_coords_lst)):
        mal_fp = f"MALGUARD{i}"
        mal_coord = mal_coords_lst[i]

        mal_fps_to_coord[mal_fp] = str(mal_coord)
        mal_fps_to_cluster[mal_fp] = lt.get_cluster(mal_coord[0], mal_coord[1])

    # insert malicious guards into network    
    for mal_fp, mal_cluster in mal_fps_to_cluster.items():
        if mal_cluster in cluster_to_fp:
            cluster_to_fp[mal_cluster].append(mal_fp)
        else:
            cluster_to_fp[mal_cluster] = [mal_fp]

    mal_dict = {k: cluster_to_fp[k] for k in mal_fps_to_cluster.values()}

    # ----------------------------------

    sum_probs = 0

    lo_client = ("unkown", 1)
    hi_client = ("unkown", 0)

    for client_coord in client_lst:

        cluster_to_dist = {}
        for idx, fps in cluster_to_fp.items():
            cluster_coord = lt.get_cluster_coord(idx)
            dist = geopy.distance.distance(client_coord, cluster_coord).km
            cluster_to_dist[idx] = dist

        sorted_dists = sorted(cluster_to_dist.items(), key=operator.itemgetter(1))
        top_clusters = [i[0] for i in sorted_dists[: int(len(sorted_dists) * g)]]

        mal_probs = {}
        for mal_fp, mal_cluster in mal_fps_to_cluster.items():
            
            if mal_cluster not in top_clusters:
                mal_guard_prob = 0
            else:
                mal_cluster_prob = 1/len(top_clusters)
                mal_guard_prob = mal_cluster_prob * 1/len(cluster_to_fp[mal_cluster])
            
            mal_probs[mal_fps_to_coord[mal_fp]] = mal_guard_prob
            

        prob = sum(mal_probs.values())

        if prob < lo_client[1]:
            lo_client = (str(client_coord), prob)
        if prob > hi_client[1]:
            hi_client = (str(client_coord), prob)

        sum_probs += prob
    
    avg_prob = sum_probs / len(client_lst)
    return (avg_prob, lo_client, hi_client)

def disp_untargeted_split_table(num_relays, bw_resource):
    """
    Prints table showing IP splitting effects on untargeted attack.

    Format:
    Relay # |relCost | vanilla prob | avg untarg prob | max untarg prob with client coord | best mal coordinate
    """

    print("Untargeted IP splitting")
    client_lst = json.load(open("../data/geoclients200.json"))
    
    mal_coords_lst = []
    fname = "attack_split_untarg/malguardprobs.json"
    res = json.load(open(fname, 'r'))

    for coord, prob in res.items():
        lat = float(coord[1:-1].split(',')[0])
        lon = float(coord[1:-1].split(',')[1])
        mal_coords_lst.append((lat, lon))


    v_distr, v_prob = vanilla.compute_vanilla_guard_distr(guard_to_bw, bw_resource)
    for i in range(0, num_relays):    
        cost = num_relays * relays.get_cost(bw_resource / num_relays)
        tot_cost = sum(guard_to_cost.values()) + cost
        rel_cost = cost / tot_cost

        res = untargeted_prob(client_lst, mal_coords_lst[:i+1], bw_resource)
        print(f"{i+1} | relCost: {rel_cost} | VT prob: {v_prob} | avg prob: {res[0]} | max prob: {res[2]} |{mal_coords_lst[i]}")

    return mal_coords_lst
    
def disp_targeted_split_table(num_relays, bw_resource):
    """
    Prints table showing IP splitting effects on targeted attack
    against client in NYC (40.6943, -73.9249).

    Format:
    Relay # |relCost | vanilla prob | cumulative targ prob | coordinate
    """
    
    print("Targeted IP splitting")
    client_coord = (40.6943, -73.9249)
    
    # emp_prob = 0
    mal_coords_lst = []
    fname = "attack_split_targ/malguardprobs.json"
    res = json.load(open(fname, 'r'))

    for coord, prob in res.items():
        lat = float(coord[1:-1].split(',')[0])
        lon = float(coord[1:-1].split(',')[1])
        mal_coords_lst.append((lat, lon))

    v_distr, v_prob = vanilla.compute_vanilla_guard_distr(guard_to_bw, bw_resource)
    for i in range(0, num_relays): 
        cost = num_relays * relays.get_cost(bw_resource / num_relays)
        tot_cost = sum(guard_to_cost.values()) + cost
        rel_cost = cost / tot_cost

        # untargeted with 1 client in client_lst   
        res = untargeted_prob([client_coord], mal_coords_lst[:i+1], bw_resource)
        print(f"{i+1} | relCost: {rel_cost} | VT prob: {v_prob} | targ LT prob: {res[0]} | {mal_coords_lst[i]}")
    
    return mal_coords_lst

def main():
    pass

if __name__ == "__main__":
    main()

