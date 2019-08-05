#!/usr/bin/env python3
"""
denasa.py
Author: Gerry Wan

"""

import json
import pickle
import sys
import copy
import pfi
import functools
from pathlib import Path

# The two ASes the DeNASA authors identified as likely to be on both the ingress
# and egress sides of a circuit.
SUSPECTS = set(["3356", "1299"])

# client to guard usability (cached for speed)
client_to_guard_usability = {}
cg_path = Path('../denasa/client_to_guard_usability.json')
if cg_path.is_file():
    # client to guard usability dict exists, open file directly
    client_to_guard_usability = json.load(open(cg_path))


# Grabbed from tempest denasa.py
def bidirectional_lookup(asn_1, asn_2, pfi):
    """
    Returns all the ASes on the forward and reverse paths between the two
    specified ASes, or None if no inference could be performed.
    """

    ases_forward_path = pfi.get_path(asn_1, asn_2)
    ases_reverse_path = pfi.get_path(asn_2, asn_1)

    if ases_forward_path is not None:
        ases_forward_path = set(ases_forward_path)

    if ases_reverse_path is not None:
        ases_reverse_path = set(ases_reverse_path)

    return union_of_non_none_sets([ases_forward_path, ases_reverse_path])

# Grabbed from tempest denasa.py
def union_of_non_none_sets(sets):
    """
    Helper function, takes a list of [set or None] and returns the union of all
    non-None elements.
    """
    return functools.reduce(lambda x, y: x.union(y), filter(lambda z: z is not\
                                                            None, sets), set())


# Modified from tempest denasa.py
def make_guard_usability_dict(client_as, fp_to_as, pfi):
    """
    Creates a dict mapping guard fingerprint to bool values.  Value is True
    if client_as can use a guard according to DeNASA's no-suspect-on-ingress
    policy, False otherwise.
    """

    if client_as in client_to_guard_usability:
        guard_to_usability = client_to_guard_usability[client_as]
    else:
        print("Create guard_to_usability from scratch")
        guard_to_usability = {}

    for guard_fp, guard_asn in fp_to_as.items():
        if guard_fp in guard_to_usability and len(guard_fp) == 40:
            # if non-malicious guard
            continue

        suspects = bidirectional_lookup(client_as, guard_asn, pfi)

        if len(suspects) == 0:
            # No path inference could be performed
            guard_to_usability[guard_fp] = False
        elif (len(suspects & SUSPECTS) != 0):
            # Suspect on path
            guard_to_usability[guard_fp] = False
        else:
            guard_to_usability[guard_fp] = True

    return guard_to_usability


def get_usable_guards(client_as, fp_to_as, pfi):
    """
    Returns a list of safe guards.

    client_as:   target client AS
    fp_to_as:    dict mapping fp to its AS
    pfi:         path file interface
    """

    # dict mapping all guard fps to bool usability
    guard_to_usability = make_guard_usability_dict(client_as, 
                                                   fp_to_as, 
                                                   pfi)


    # filter
    guard_to_usability = {fp:guard_to_usability[fp] for fp in fp_to_as}

    safe_guard_fps = list(filter(lambda x: guard_to_usability[x],
                                guard_to_usability.keys()))

    return safe_guard_fps


def get_usable_mal_guard_ases(client_as, all_ases, pfi):
    """
    Creates a list of all ASes that a client can place a usable guard in
    according to DeNASA's no-suspect-on-ingress policy
    *Warning: slow for len(ALL_ASES) > a couple thousand*
    """

    if client_as in SUSPECTS:
        return []

    usable_mal_guard_ases = []
    
    cnt = 0
    for asn in all_ases:
        suspects = bidirectional_lookup(client_as, asn, pfi)

        if len(suspects) != 0 and len(suspects & SUSPECTS) == 0:
            usable_mal_guard_ases.append(asn)

        cnt += 1
        # if cnt % 1000 == 0:
        #     print(len(usable_mal_guard_ases))

    return usable_mal_guard_ases

def get_first_usable_mal_guard_as(client_as, all_ases, pfi):
    """
    Creates a size 1 list of the first AS that a client can place a usable guard in
    according to DeNASA's no-suspect-on-ingress policy
    """

    if client_as in SUSPECTS:
        return []

    for asn in all_ases:
        suspects = bidirectional_lookup(client_as, asn, pfi)

        if len(suspects) != 0 and len(suspects & SUSPECTS) == 0:
            return [asn]

def make_guard_fp_to_bw(safe_fp_to_bw, malicious_fp_to_bw):
    """
    Returns a dict mapping each guard FP to bandwidth

    safe_fp_to_bw:      dict mapping innocent guard FPs to bandwidth
    malicious_fp_to_bw: dict mapping malicious guard FPs to bandwidth
    """

    guard_fp_to_bw = {}

    # add innocent guards
    for guard_fp, bw in safe_fp_to_bw.items():
        guard_fp_to_bw[guard_fp] = bw

    # add malicious guards
    for guard_fp, bw in malicious_fp_to_bw.items():
        guard_fp_to_bw[guard_fp] = bw

    return guard_fp_to_bw

def compute_prob(client_as, 
                mal_guard_fp,
                mal_guard_bw,
                network_state,
                pfi):
    """
    Returns probability of client in client_as selecting mal_guard_fp
    with bandwidth mal_guard_bw, given current network_state.
    The current network_state has this guard already inserted.

    client_as: client AS
    mal_guard_fp: FP of malicious guard
    mal_guard_bw: BW of malicious guard 
    network_state: dict mapping guard FP to (AS, bw) tuple
    pfi: path file interface
    """
    
    # unpack network state
    fp_to_as = {k:v[0] for k,v in network_state.items()}
    fp_to_bw = {k:v[1] for k,v in network_state.items()}

    safe_guard_fps = get_usable_guards(client_as, fp_to_as, pfi)

    if len(safe_guard_fps) == 0:
        bw_sum = sum(fp_to_bw.values())
        prob = mal_guard_bw / bw_sum

    else:
        if mal_guard_fp not in safe_guard_fps:
            prob = 0

        else:
            bw_sum = sum(map(lambda x: fp_to_bw[x], safe_guard_fps))
            prob = mal_guard_bw / bw_sum

    return prob

def compute_untargeted_prob(client_as_lst, 
                            bw_resource,
                            num_relays,
                            guard_to_bw,
                            all_ases,
                            ip_to_as,
                            pfi,
                            outDir):
    """
    Returns the average selection probability of selecting the malicious
    guard over all clients in client_as_lst, as well as the hardest 
    and easiest client to attack if the malicious guard is placed in 
    mal_guard_as.
    *Computes the optimal attack locations using greedy algorithm*

    client_as_lst: list of target set
    bw_resource:   total bw resource
    num_relays:    number of malicious guards
    guard_to_bw:   dict mapping innocent guards to bandwidth
    all_ases:      list of candidate ASes
    ip_to_as:      dict mapping IP to ASN
    pfi:           path file interface
    """

    mal_guard_probs = {}
    mal_guard_bw = bw_resource / num_relays

    # initial network state (no malicious guards yet)
    # format: {FP: (AS, BW)}
    network_state = {}
    for g, bw in guard_to_bw.items():
        network_state[g.fingerprint] = (ip_to_as[g.address], bw)

    for i in range(0, num_relays):

        mal_guard_fp = f"MALGUARD{i}"

        # avg_prob, i^{th} mal_as, network_state
        best_state = (0, "unknown", {})

        cnt = 0
        for cand_as in all_ases:

            # insert malicious guard in candidate AS
            temp_network_state = copy.deepcopy(network_state)
            temp_network_state[mal_guard_fp] = (cand_as, mal_guard_bw)
            
            sum_probs = 0
            for client_as in client_as_lst:
                prob = compute_prob(client_as,
                                    mal_guard_fp, 
                                    mal_guard_bw, 
                                    temp_network_state,
                                    pfi)
                sum_probs += prob
            avg_prob = sum_probs / len(client_as_lst)

            cnt += 1
            print(cnt)

            if avg_prob > best_state[0]:
                best_state = (avg_prob, cand_as, copy.deepcopy(temp_network_state))

        network_state = copy.deepcopy(best_state[2])
        mal_guard_probs[f'{best_state[1]}_{i}'] = best_state[0]

        if outDir is not None:
            json.dump(best_state, open(f"{outDir}/tempbeststate{i}.json", "w"))

    print(mal_guard_probs)
    if outDir is not None:
        json.dump(mal_guard_probs, open(f"{outDir}/malguardprobs.json", "w"))
    print(sum(mal_guard_probs.values()))

    return mal_guard_probs


# Modified from tempest denasa.py
def compute_denasa_guard_distr(client_as, guard_to_bw, mal_guard_bw, 
                                ip_to_as, all_ases, pfi):
    """
    ATTACK function (inserts optimal malicious guard)
    Returns a dict mapping each DeNASA guard to its selection probability
    and the probability an adversary's guard is chosen
    * Only for targeted attacks *

    client_as:    target AS
    guard_to_bw:  dict mapping guard to bandwidth
    mal_guard_bw: bandwidth resource of adversary
    ip_to_as:     dict mapping IP to ASN
    all_ases:     candidate ASes to place malicious guard
    pfi:          path file interface
    """

    print(f"ClientAS: {client_as}")
    print(f"Bandwidth resource: {mal_guard_bw}")

    guards = list(guard_to_bw.keys())
    fp_to_bw = {}
    fp_to_as = {}
    for guard in guards:
        fp_to_bw[guard.fingerprint] = guard_to_bw[guard]
        fp_to_as[guard.fingerprint] = ip_to_as[guard.address]

    safe_guard_fps = get_usable_guards(client_as, fp_to_as, pfi)
    print("Num safe guards: %d" % len(safe_guard_fps))
    
    usable_mal_guard_ases = get_first_usable_mal_guard_as(client_as, all_ases, pfi)
    if len(usable_mal_guard_ases) == 0:
        mal_guard_fp = "ASn"
    else:
        mal_guard_fp = f"AS{usable_mal_guard_ases[0]}"

    malicious_fp_to_bw = {mal_guard_fp: mal_guard_bw}
    safe_fp_to_bw = dict((fp, fp_to_bw[fp]) for fp in safe_guard_fps)

    guard_fp_to_bw = make_guard_fp_to_bw(safe_fp_to_bw, malicious_fp_to_bw)


    if len(usable_mal_guard_ases) == 0:
        # if there is no usable/safe malicious guard placement

        mal_guard_fp = "ASn"
        if len(safe_fp_to_bw) == 0:
            # If there are no safe guards at all, resort back to vanilla bandwidth
            # weighting
            bw_sum = sum(guard_to_bw.values()) + mal_guard_bw
            all_guard_probs = {g.fingerprint: bw/bw_sum for (g, bw) in guard_to_bw.items()}
            mal_guard_prob = mal_guard_bw / bw_sum
            all_guard_probs[mal_guard_fp] = mal_guard_prob
            print("DeNASA probability (resort to Vanilla): %f" % mal_guard_prob)

        else:
            # If there are safe innocent guards, but no safe malicious guard placement
            # (this scenario should never happen)
            print("Error: safe innocent guard locations, but no safe malicious guard locations")
    
    else:
        bw_sum = sum(guard_fp_to_bw.values())
        all_guard_probs = {fp: bw/bw_sum for (fp, bw) in guard_fp_to_bw.items()}
        mal_guard_prob = all_guard_probs[mal_guard_fp]
        print("DeNASA probability: %f" % mal_guard_prob)

    # set the probability of choosing any unsafe guards to 0 (for the full distribution)
    for fp in fp_to_bw:
        if fp not in all_guard_probs:
            all_guard_probs[fp] = 0

    return all_guard_probs, mal_guard_prob


# Modified from tempest denasa.py
def compute_dn_selection_probs(client_as,
                                fp_to_bw,
                                fp_to_as, 
                                all_ases, 
                                pfi):
    """
    Returns a dict mapping client AS to its DeNASA guard selection probability,
    no malicious guard insertion.
    """

    print(f"ClientAS: {client_as}")

    safe_guard_fps = get_usable_guards(client_as, fp_to_as, pfi)
    print("Num safe guards: %d" % len(safe_guard_fps))

    safe_fp_to_bw = dict((fp, fp_to_bw[fp]) for fp in safe_guard_fps)

    bw_sum = sum(safe_fp_to_bw.values())
    if len(safe_guard_fps) == 0 or bw_sum == 0:
        # if there are no safe guards, resort to Vanilla
        bw_sum = sum(fp_to_bw.values())

        # if all guards have 0 bandwidth weighting, uniformly distribute (rare)
        if bw_sum == 0:
            print("all guards have 0 weight")
            selection_probs = {fp: 1/len(fp_to_bw) for fp in fp_to_bw}
        else:
            print("resorting to vanilla")
            selection_probs = {fp: bw/bw_sum for (fp, bw) in fp_to_bw.items()}
        return selection_probs

    else:
        
        selection_probs = dict.fromkeys(fp_to_bw, 0)

        for safe_guard_fp in safe_guard_fps:
            selection_probs[safe_guard_fp] = safe_fp_to_bw[safe_guard_fp] / bw_sum

        return selection_probs

