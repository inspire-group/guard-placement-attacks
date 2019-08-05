#!/usr/bin/env python3
"""
selection_analysis_DN.py
Author: Gerry Wan

Functions for performing selection probability analysis in DeNASA.
"""

import sys

sys.path.append('..')
sys.path.append('../vanilla')

import numpy as np
import argparse
import denasa
import pfi
import vanilla
import json
import pickle
import operator
import relays

paths_filename = "as_paths.txt"
index_filename = "as_paths_index.bin"
libspookyhash_filename = "./libspookyhash.so"

ip_to_as = json.load(open("../guard_info/ip_to_as.json"))
all_ases = [asn.strip() for asn in open("../data/relay_ases.txt", 'r').readlines()]
guard_to_bw = pickle.load(open("../guard_info/guard_to_bw.pickle", "rb"))
guard_to_cost = {guard: relays.get_cost(bw) for guard, bw in guard_to_bw.items()}

pfi_instance = pfi.PFI(libspookyhash_filename,
                paths_filename,
                index_filename)

pfi_instance.load()
pfi_instance.verify()

def parse_args():
    parser = argparse.ArgumentParser()
    return parser.parse_args()

def make_topnclient_prob_matrix(client_as_lst, bw_resources_lst, best_as_dict):
    """
    Returns a numpy matrix where every row corresponds to the bandwidth

    col_0: Vanilla Tor selection probability
    col_1: Untargeted DN average selection probability (across all clients)
    col_2: Untargeted DN lowest selection probability
    col_3: Untargeted DN highest selection probability
   

    client_as_lst:      set of target client ASes 
    bw_resources_lst:   list containing bandwidth resources
    best_as:            best_as for DeNASA untargeted against top368 clients.
                        This happens to be AS1659
    """

    prob_matrix = np.zeros(shape=(len(bw_resources_lst), 4))

    for i in range(0, len(bw_resources_lst)):
        bw_resource = bw_resources_lst[i]
        print(f"Bandwidth: {bw_resource}")

        # ----------- Vanilla -----------

        v_guard_probs, v_prob = vanilla.compute_vanilla_guard_distr(guard_to_bw, bw_resource)
        prob_matrix[i][0] = v_prob

        # ----------- Untargeted DN -----------

        best_as_untargeted = best_as_dict[str(bw_resource)]

        untargeted_prob_triple = untargeted_prob(client_as_lst, 
                                                [best_as_untargeted],
                                                [bw_resource],
                                                pfi_instance)
        avg_prob = untargeted_prob_triple[0]
        lo_client = untargeted_prob_triple[1]
        hi_client = untargeted_prob_triple[2]

        prob_matrix[i][1] = avg_prob
        prob_matrix[i][2] = lo_client[1]
        prob_matrix[i][3] = hi_client[1]

        print(f"average prob: {avg_prob}")
        print(f"lo client untargeted prob: {lo_client}")
        print(f"hi client untargeted prob: {hi_client}")

    return prob_matrix



def get_top_mal_guard_ases(client_as_lst, bw_resources_lst):
    """
    Returns a dict mapping top malicious guard placements to average
    selection probability among clients in client_as_lst.
    """

    for bw in bw_resources_lst:
        top = {}
        cnt = 0
        for mal_guard_as in all_ases:
            cnt += 1
            print(cnt)
            res_triple = untargeted_prob(client_as_lst,
                                        [mal_guard_as],
                                        [bw],
                                        pfi_instance)
            print(res_triple)
            top[mal_guard_as] = res_triple[0]
       
        sorted_top = sorted(top.items(), key=operator.itemgetter(1))
        sorted_top.reverse()
        topn = sorted_top
        print(topn)

        json.dump(topn, open(f'best_mal_ases_{bw}.json', 'w'))


def dump_best_untargeted_as(bw_resources_lst):
    """
    Returns list of optimal AS locations depending on bandwidth
    for single-guard untargeted attack.
    """

    best_untargeted_ases = {}
    for bw in bw_resources_lst:
        fname =  f"best/best_mal_ases_{bw}.json"
        top_ases = json.load(open(fname))
        best_untargeted_ases[bw] = top_ases[0][0]

    json.dump(best_untargeted_ases, open("best_ases_untarg.json","w"))



def get_client_to_targeting_advantage(client_as_lst, bw_resource, best_as):
    """
    Returns a dict mapping client AS to targeting advantage.

    client_as_lst:      set of target client ASes 
    bw_resource:        bandwidth resource
    best_as:            best_as for DeNASA untargeted against top368 clients.
                        This happens to be AS1659
    """
    best_as_untargeted = best_as  # empirically determined

    tadv = {}

    cnt = 0
    for client_as in client_as_lst:
        print(cnt)
        cnt += 1

        untargeted_prob_triple = untargeted_prob([client_as], 
                                                [best_as_untargeted],
                                                [bw_resource], 
                                                pfi_instance)
        dn_prob_untargeted = untargeted_prob_triple[0]

        dn_distr, dn_prob = denasa.compute_denasa_guard_distr(client_as,
                                                guard_to_bw, 
                                                bw_resource, 
                                                ip_to_as, 
                                                all_ases,
                                                pfi_instance)
 
        tadv[client_as] = (dn_prob_untargeted, dn_prob)

    return tadv



def disp_untargeted_split_table_avg(client_as_lst, bw_resource, num_relays_lst):
    """
    Prints table showing varying relays effect on untargeted attack
    (average success).

    Format:
    Relay # | relCost | vanilla prob | avg untarg prob | max untarg prob with client AS 
    """


    v_guard_probs, v_prob = vanilla.compute_vanilla_guard_distr(guard_to_bw, bw_resource)

    for num_relays in num_relays_lst:
        inDir = f"untarg{num_relays}"
        mal_guard_as_lst = []
        for i in range(num_relays):
            fname = f"{inDir}/tempbeststate{i}.json"
            best_state = json.load(open(fname))
            mal_guard_as_lst.append(best_state[1])

        bw_per_guard = bw_resource / num_relays
        mal_guard_bw_lst = [bw_per_guard] * num_relays

        
        res_triple = untargeted_prob(client_as_lst,
                                    mal_guard_as_lst,
                                    mal_guard_bw_lst,
                                    pfi_instance)
        avg_prob = res_triple[0]
        hi_prob = res_triple[2]  # tuple of (client AS, prob)

        cost = num_relays * relays.get_cost(bw_resource / num_relays)
        tot_cost = sum(guard_to_cost.values()) + cost
        rel_cost = cost / tot_cost

        print(f"{num_relays} | relCost: {rel_cost} | VT prob: {v_prob} | avg prob: {avg_prob} | max prob: {hi_prob}")


def disp_max_advantages(client_as_lst, bw_resources_lst, best_as_dict):
    """
    Display maximum attacker advantage in untargeted attack compared to
    Vanilla Tor and relCost.
    """
    for i in range(0, len(bw_resources_lst)):
        bw_resource = bw_resources_lst[i]
        v_guard_probs, v_prob = vanilla.compute_vanilla_guard_distr(guard_to_bw, bw_resource)
        rel_cost = relays.get_cost(bw_resource) / (relays.get_cost(bw_resource)+sum(guard_to_cost.values()))

        best_as_untargeted = best_as_dict[str(bw_resource)]
        untargeted_prob_triple = untargeted_prob(client_as_lst, 
                                            [best_as_untargeted],
                                            [bw_resource], 
                                            pfi_instance)
        print(bw_resource)
        print("avg")
        print(untargeted_prob_triple[0] / v_prob)
        print(untargeted_prob_triple[0] / rel_cost)

        print("max")
        print(untargeted_prob_triple[2][1] / v_prob)
        print(untargeted_prob_triple[2][1] / rel_cost)


def untargeted_prob(client_as_lst, 
                        mal_guard_as_lst,
                        mal_guard_bw_lst, 
                        pfi):
    """
    Returns the average selection probability of selecting the malicious
    guard over all clients in client_as_lst, as well as the hardest 
    and easiest client to attack if the malicious guards are placed in 
    mal_guard_as_lst.
    *Does not compute optimal guard placement locations.*

    client_as_lst: list of target set
    mal_guard_as_lst: list of malicious guard locations
    mal_guard_bw_lst: list of malicious guard bandwidths
    pfi:           path file interface
    """
    
    guards = list(guard_to_bw.keys())
    fp_to_bw = {}
    fp_to_as = {}
    for guard in guards:
        fp_to_bw[guard.fingerprint] = guard_to_bw[guard]
        fp_to_as[guard.fingerprint] = ip_to_as[guard.address]

    mal_guard_fp_lst = [f"AS{mal_guard_as}_{i}" for i, mal_guard_as in enumerate(mal_guard_as_lst)]
    for i in range(len(mal_guard_fp_lst)):
        fp = mal_guard_fp_lst[i]
        fp_to_bw[fp] = mal_guard_bw_lst[i]
        fp_to_as[fp] = mal_guard_as_lst[i]

    print(mal_guard_fp_lst)

    sum_probs = 0
    lo_client = ("unknown", 1)
    hi_client = ("unknown", 0)

    for client_as in client_as_lst:
        safe_guard_fps = denasa.get_usable_guards(client_as, fp_to_as, pfi)

        if len(safe_guard_fps) == 0:
            #print("no usable guards, resort to vanilla")
            bw_sum = sum(fp_to_bw.values())
            prob = sum(mal_guard_bw_lst) / bw_sum

        else:
            bw_sum = sum(map(lambda x: fp_to_bw[x], safe_guard_fps))
            safe_mal_guard_fps = [fp for fp in safe_guard_fps if fp.startswith('AS')]
            mal_guard_bw_sum = sum(map(lambda x: fp_to_bw[x], safe_mal_guard_fps))
            prob = mal_guard_bw_sum / bw_sum

        if prob < lo_client[1]:
            lo_client = (client_as, prob)
        if prob > hi_client[1]:
            hi_client = (client_as, prob)
        sum_probs += prob


    avg_prob = sum_probs / len(client_as_lst)
    
    return (avg_prob, lo_client, hi_client)


def main(args):
    pass

if __name__ == "__main__":
    main(parse_args())
