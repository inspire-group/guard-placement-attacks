#!/usr/bin/env python3
"""
vanilla.py
Author: Gerry Wan

"""

def compute_vanilla_guard_distr(guard_to_bw, mal_guard_bw):
    """
    Returns a dict mapping each Vanilla guard fingerprint to its 
    selection probability and the probability of the malicious guard 
    being chosen.

    guard_to_bw:  dict mapping innocent guards to bandwidth
    mal_guard_bw: bandwidth the adversary is willing to provide
    """

    sum_bw = sum(guard_to_bw.values()) + mal_guard_bw

    all_guard_probs = {guard.fingerprint: bw/sum_bw for (guard, bw) in guard_to_bw.items()}
    mal_guard_prob = mal_guard_bw / sum_bw
    all_guard_probs["MALGUARD"] = mal_guard_prob
    print("Vanilla probability: %f" % mal_guard_prob)

    return all_guard_probs, mal_guard_prob
