#!/usr/bin/env python3
"""
selection_analysis_CR.py
Author: Gerry Wan

Functions for performing selection probability analysis in Counter-RAPTOR.
"""

import sys

sys.path.append('..')
sys.path.append('../vanilla')

import numpy as np
import argparse
import counterraptor as cr
import vanilla
import json
import pickle
import relays


# ------- init info ------------------

client_to_all_res = json.load(open("all_reachable_resilience.json"))
client_to_guard_res = json.load(open("cg_resilience.json"))
client_as_lst = list(client_to_guard_res.keys())

ip_to_as = json.load(open("../guard_info/ip_to_as.json"))
guard_to_bw = pickle.load(open("../guard_info/guard_to_bw.pickle", "rb"))
guard_to_cost = {guard: relays.get_cost(bw) for guard, bw in guard_to_bw.items()}

alpha = 0.5
sample_size = int(0.1*len(guard_to_bw))     # g = 0.1

# ------------------------------------

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target_as")
    return parser.parse_args()


def get_client_to_targeting_advantage(client_as_lst, bw_resource, num_relays):
    """
    Returns a dict mapping client AS to targeting advantage.

    client_as_lst:      set of target client ASes 
    bw_resources:       bandwidth resources
    num_relays:         number of relays
    """

    # --------------- compute targeting advantage --------------
    teffs = {}

    best_as_untargeted = cr.compute_attack_as(client_as_lst, 
                                                client_to_all_res,
                                                client_to_guard_res,
                                                guard_to_bw,
                                                ip_to_as,
                                                sample_size)
    print(f"Optimal untargeted AS for {best_as_untargeted}")

    cnt = 0
    max_targadv = ("unknown", 0, 0, 0)  # client AS, targadv, cr_prob, cr_untarg
    num_same = 0
    for client_as in client_as_lst:
        best_as = cr.compute_attack_as([client_as], 
                                                client_to_all_res,
                                                client_to_guard_res,
                                                guard_to_bw,
                                                ip_to_as,
                                                sample_size)
        cr_distr, cr_prob = cr.compute_cr_guard_distr(client_as,
                                                best_as,
                                                client_to_all_res, 
                                                client_to_guard_res,
                                                guard_to_bw, 
                                                ip_to_as,
                                                num_relays,
                                                bw_resource,
                                                alpha,
                                                sample_size)
        cr_distr_untargeted, cr_prob_untargeted = cr.compute_cr_guard_distr(client_as, 
                                                best_as_untargeted, 
                                                client_to_all_res,
                                                client_to_guard_res,
                                                guard_to_bw, 
                                                ip_to_as,
                                                num_relays,
                                                bw_resource,
                                                alpha,
                                                sample_size)
        targadv = cr_prob / cr_prob_untargeted
        if targadv > max_targadv[1]:
            max_targadv = (client_as, targadv, cr_prob, cr_prob_untargeted)
        if targadv == 1:
            num_same += 1

        teffs[client_as] = (cr_prob_untargeted, cr_prob)

    print(max_targadv)
    print(f"num same: {num_same}")
    return teffs


def make_topnclient_prob_matrix(client_as_lst, bw_resources_lst, num_relays_lst):
    """
    Returns a numpy matrix where every row corresponds to the relCost
    given bandwidth

    col_0: Vanilla Tor selection probability
    col_1: Untargeted CR average selection probability (across all clients)
    col_2: Untargeted CR lowest selection probability
    col_3: Untargeted CR highest selection probability
    col_4: Targeted CR against client with lowest untargeted selection probability
    col_5: Targeted CR against client with highest untargeted selection probability

    client_as_lst:      set of target client ASes 
    bw_resources_lst:   list containing bandwidth resources
    num_relays_lst:     list containing number of relays (for now, list of size 1)
    """

    # temporary, to avoid clutter
    num_relays = num_relays_lst[0]


    prob_matrix = np.zeros(shape=(len(bw_resources_lst), 6))

    for i in range(0, len(bw_resources_lst)):
        bw_resource = bw_resources_lst[i]
        print(f"Bandwidth: {bw_resource}")

        # ----------- Vanilla -----------

        v_guard_probs, v_prob = vanilla.compute_vanilla_guard_distr(guard_to_bw, bw_resource)
        prob_matrix[i][0] = v_prob

        # ----------- Untargeted CR -----------

        best_as_untargeted = cr.compute_attack_as(client_as_lst, 
                                                client_to_all_res,
                                                client_to_guard_res,
                                                guard_to_bw,
                                                ip_to_as,
                                                sample_size)

        print(f"Optimal adversary AS for untargeted CR: {best_as_untargeted}")

        sum_prob = 0

        # client with lowest selection probability for optimal untargeted guard placement.
        # this is the hardest client to attack
        lo_client = ("unknown", 1)

        # client with highest selection probability for optimal untargeted guard placement.
        # this is the easiest client to attack
        hi_client = ("unknown", 0)

        for client_as in client_as_lst:
            all_guard_probs, mal_guard_prob = cr.compute_cr_guard_distr(client_as, 
                                                            best_as_untargeted, 
                                                            client_to_all_res,
                                                            client_to_guard_res,
                                                            guard_to_bw, 
                                                            ip_to_as,
                                                            num_relays,
                                                            bw_resource,
                                                            alpha,
                                                            sample_size)
            sum_prob += mal_guard_prob

            if mal_guard_prob < lo_client[1]:
                lo_client = (client_as, mal_guard_prob)
            if mal_guard_prob > hi_client[1]:
                hi_client = (client_as, mal_guard_prob)

        avg_prob = sum_prob / len(client_as_lst)

        prob_matrix[i][1] = avg_prob
        prob_matrix[i][2] = lo_client[1]
        prob_matrix[i][3] = hi_client[1]

        print(f"average prob: {avg_prob}")
        print(f"lo client untargeted prob: {lo_client[0]}, {lo_client[1]}")
        print(f"hi client untargeted prob: {hi_client[0]}, {hi_client[1]}")

    return prob_matrix

def make_topnclient_prob_matrix_relative(client_as_lst, bw_resources_lst, num_relays_lst):
    """
    Returns a numpy matrix where every row corresponds to the bandwidth
    the adversary is willing to provide, every column corresponds to the
    number of relays the adversary is willing to run, and each cell
    contains the relative efficiency of the attack

    client_as_lst:    list of target ASes 
    bw_resources_lst: list containing bandwidth resources
    num_relays_lst:   list containing number of relays
    """


    prob_matrix = np.zeros(shape=(len(bw_resources_lst), len(num_relays_lst)))

    for i in range(0, len(bw_resources_lst)):
        bw_resource = bw_resources_lst[i]
        v_guard_probs, v_prob = vanilla.compute_vanilla_guard_distr(guard_to_bw, bw_resource)

        best_as_untargeted = cr.compute_attack_as(client_as_lst, 
                                                client_to_all_res,
                                                client_to_guard_res,
                                                guard_to_bw,
                                                ip_to_as,
                                                sample_size)
        print(f"Optimal adversary AS for untargeted CR: {best_as_untargeted}")

        for j in range(0, len(num_relays_lst)):
            num_relays = num_relays_lst[j]
            
            sum_prob = 0
            for client_as in client_as_lst:
                all_guard_probs, mal_guard_prob = cr.compute_cr_guard_distr(client_as, 
                                                                best_as_untargeted, 
                                                                client_to_all_res,
                                                                client_to_guard_res,
                                                                guard_to_bw, 
                                                                ip_to_as,
                                                                num_relays,
                                                                bw_resource,
                                                                alpha,
                                                                sample_size)
                sum_prob += mal_guard_prob
            avg_prob = sum_prob / len(client_as_lst) 

            prob_matrix[i][j] = avg_prob / v_prob

    return prob_matrix

def make_client_prob_matrix_bw_to_relays(client_as, bw_resources_lst, num_relays_lst):
    """
    Returns a numpy matrix where every row corresponds to the bandwidth
    the adversary is willing to provide, every column corresponds to the
    number of relays the adversary is willing to run, and each cell
    contains the probability of the client choosing a malicious guard

    The first column contains the Vanilla selection probabilities

    client_as:        target AS 
    bw_resources_lst: list containing bandwidth resources
    num_relays_lst:   list containing number of relays
    """


    prob_matrix = np.zeros(shape=(len(bw_resources_lst), len(num_relays_lst) + 1))

    for i in range(0, len(bw_resources_lst)):
        bw_resource = bw_resources_lst[i]
        v_guard_probs, v_prob = vanilla.compute_vanilla_guard_distr(guard_to_bw, bw_resource)
        prob_matrix[i][0] = v_prob

        for j in range(0, len(num_relays_lst)):
            num_relays = num_relays_lst[j]

            best_as = cr.compute_attack_as([client_as], 
                                                client_to_all_res,
                                                client_to_guard_res,
                                                guard_to_bw,
                                                ip_to_as,
                                                sample_size)

            cr_distr, cr_prob = cr.compute_cr_guard_distr(client_as, 
                                                best_as,
                                                client_to_all_res, 
                                                client_to_guard_res,
                                                guard_to_bw, 
                                                ip_to_as,
                                                num_relays,
                                                bw_resource,
                                                alpha,
                                                sample_size)

            prob_matrix[i][j+1] = cr_prob

    return prob_matrix

def disp_targeted_split_table(client_as, bw_resource, num_relays_lst):
    """
    Prints table showing varying relays effect targeted attack.
    """
    
    best_as = cr.compute_attack_as([client_as], 
                                    client_to_all_res,
                                    client_to_guard_res,
                                    guard_to_bw,
                                    ip_to_as,
                                    sample_size)
    v_guard_probs, v_prob = vanilla.compute_vanilla_guard_distr(guard_to_bw, bw_resource)
    
    for num_relays in num_relays_lst:
        all_guard_probs, mal_prob = cr.compute_cr_guard_distr(client_as, 
                                                        best_as, 
                                                        client_to_all_res,
                                                        client_to_guard_res,
                                                        guard_to_bw, 
                                                        ip_to_as,
                                                        num_relays,
                                                        bw_resource,
                                                        alpha,
                                                        sample_size)

        cost = num_relays * relays.get_cost(bw_resource / num_relays)
        tot_cost = sum(guard_to_cost.values()) + cost
        rel_cost = cost / tot_cost

        print(f"{num_relays} | relCost: {rel_cost} | VT prob: {v_prob} | targ CR prob: {mal_prob} | AS{best_as}")


def disp_untargeted_split_table_avg(client_as_lst, 
                                best_as_untargeted,
                                bw_resource, 
                                num_relays_lst):
    """
    Prints table showing varying relays effect on untargeted attack
    (average success).
    """
    

    v_guard_probs, v_prob = vanilla.compute_vanilla_guard_distr(guard_to_bw, bw_resource)
    
    for num_relays in num_relays_lst:
        sum_probs = 0
        for client_as in client_as_lst:
            all_guard_probs, mal_guard_prob = cr.compute_cr_guard_distr(client_as, 
                                                            best_as_untargeted, 
                                                            client_to_all_res,
                                                            client_to_guard_res,
                                                            guard_to_bw, 
                                                            ip_to_as,
                                                            num_relays,
                                                            bw_resource,
                                                            alpha,
                                                            sample_size)
            sum_probs += mal_guard_prob
        mal_prob = sum_probs / len(client_as_lst)

        cost = num_relays * relays.get_cost(bw_resource / num_relays)
        tot_cost = sum(guard_to_cost.values()) + cost
        rel_cost = cost / tot_cost

        print(f"{num_relays} | relCost: {rel_cost} | VT prob: {v_prob} | utarg CR prob: {mal_prob} | AS{best_as_untargeted}")


def main(args):
    pass


if __name__ == "__main__":
    main(parse_args())
