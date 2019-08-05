#!/usr/bin/env python3
"""
counterraptor.py
Author: Gerry Wan

"""
import json
import pickle

best_targeted = json.load(open('../counterraptor/best_targeted.json'))

# Grabbed from counter_raptor_guard.py
def helper_calc(lst,k):
    s = sum(lst)
    for i in range(0,len(lst)):
        lst[i] = (lst[i]*k)/s
    return lst

# Grabbed from counter_raptor_guard.py
def recalcprob(lst,k):
    tmplst = helper_calc(lst,k)
    finallst = [0] * len(tmplst)
    counter = 0
    while max(tmplst) > 1:
        for i in range(0,len(tmplst)):
            if tmplst[i] > 1:
                finallst[i] = 1
                tmplst[i] = 0
                counter += 1
        if max(tmplst) > 0:
            tmplst = helper_calc(tmplst,k-counter)
        else:
            break
    for i in range(0,len(tmplst)):
        if tmplst[i] != 0:
            finallst[i] = tmplst[i]
    return [i/k for i in finallst]


def adjust_resilience(guard_fp_to_res, sample_size):
    """
    Adjust resiliences of each relay using Tille's algorithm

    guard_fp_to_res: dict mapping guard FP to unrandomized resilience
    sample_size:     1 means no sampling, N means all relays equal
    """
    adjusted = {}
    
    fps = list(guard_fp_to_res.keys())
    res = recalcprob(list(guard_fp_to_res.values()), sample_size)

    for i in range(0, len(fps)):
        fp = fps[i]
        adjusted_resilience = res[i]
        adjusted[fp] = adjusted_resilience

    return adjusted

def compute_attack_as(client_as_lst, 
                    client_to_all_res,
                    client_to_guard_res, 
                    guard_to_bw, 
                    ip_to_as, 
                    sample_size):
    """
    Returns a tuple (ASN, resilience) of the best AS to place a malicious guard such
    that it receives a high resilience weighting. There could exist multiple optimal
    ASes, pick one.

    client_as_lst:      list of target ASes
    client_to_all_res:  dict mapping clients to resiliences from each AS
    """

    if len(client_as_lst) == 1 and client_as_lst[0] in best_targeted:
        return best_targeted[client_as_lst[0]]

    cand_ases = list(client_to_all_res[client_as_lst[0]].keys())

    best_as = ('unknown', 0)
    cnt = 0
    for cand_as in cand_ases:

        sum_norm_res_over_clients = 0
        for client_as in client_as_lst:
            cand_res = client_to_all_res[client_as][cand_as]

            malicious_fp_to_res = make_malicious_fp_to_res(1, cand_as, cand_res)
            guard_as_resiliences = client_to_guard_res[client_as]
            guard_list = list(guard_to_bw.keys())
            guard_fp_to_res = make_guard_fp_to_res(guard_as_resiliences,
                                                    malicious_fp_to_res,
                                                    guard_list,
                                                    ip_to_as)
            guard_fp_to_res_adj = adjust_resilience(guard_fp_to_res, sample_size)

            sum_res = sum(guard_fp_to_res_adj.values())
            #print(sum_res)
            
            res_distr = {fp: res/sum_res for (fp, res) in guard_fp_to_res_adj.items()}
            res_norm = sum([res for (fp, res) in res_distr.items() if fp.startswith('AS')])

            sum_norm_res_over_clients += res_norm

        if sum_norm_res_over_clients > best_as[1]:
            best_as = (cand_as, sum_norm_res_over_clients)

        cnt += 1

    return best_as[0]

def find_attack_as_lowest_resilience(mal_location, 
                                    client_as_lst, 
                                    client_to_all_res):
    """
    Returns a tuple (client_as, resilience) for the target client AS that 
    the mal_location has the lowest resilience from.

    mal_location:      AS location of guard
    client_as_lst:     list of client ASes
    client_to_all_res: dict mapping clients to resilience from all reachable ASes
    """

    worst_target = ("unknown", 1)
    for client_as in client_as_lst:
        res = client_to_all_res[client_as][mal_location]
        if res < worst_target[1]:
            worst_target = (client_as, res)
    return worst_target

def find_optimal_client_adv_pair(client_as_lst, 
                                guard_as_lst, 
                                client_to_all_res):
    """
    Returns a triple (client_as, adv_as, resilience) for easiest client to attack 
    and the optimal location the adversary should place a guard to attack that 
    client.

    client_as_lst:     list of client ASes
    guard_as_lst:      list of reachable ASes
    client_to_all_res: dict mapping clients to resilience from all reachable ASes
    """

    best_pair = ("unknown", "unknown", 0)
    for client_as in client_as_lst:
        for guard_as in guard_as_lst:
            res = client_to_all_res[client_as][guard_as]
            if res > best_pair[2]:
                best_pair = (client_as, guard_as, res)
    return best_pair


def make_malicious_fp_to_res(num_relays, best_as, best_res):
    """
    Returns a dict mapping malicious guard FPs to resilience

    Malicious guard FP follows the format: AS{0}_RELAY{1}
    {0}: ASN
    {1}: Relay number (0 to num_relays-1)
    """

    malicious_fp_to_res = {}

    for i in range(0, num_relays):
        malicious_fp = f"AS{best_as}_RELAY{i}"
        malicious_fp_to_res[malicious_fp] = best_res

    return malicious_fp_to_res


def make_malicious_fp_to_bw(num_relays, best_as, bw_resource):
    """
    Returns a dict mapping malicious guard FPs to bandwidth

    Malicious guard FP follows the format: AS{0}_RELAY{1}
    {0}: ASN
    {1}: Relay number (0 to num_relays-1)
    """

    malicious_fp_to_bw = {}

    # split bandwidth resource among malicious relays
    relay_bw = bw_resource / num_relays

    for i in range(0, num_relays):
        malicious_fp = f"AS{best_as}_RELAY{i}"
        malicious_fp_to_bw[malicious_fp] = relay_bw

    return malicious_fp_to_bw


def make_guard_fp_to_res(guard_as_resiliences, malicious_fp_to_res, guard_list, ip_to_as):
    """
    Returns a dict mapping each guard FP to resilience (non Tille sampled)

    guard_as_resiliences: dict mapping innocent guard ASes to resilience 
                         (non Tille sampled). This is computed by cg_resilience.py
    malicious_fp_to_res: dict mapping malicious guard FPs to resilience
                         (non Tille sampled).
    guard_list:          list of innocent guards
    ip_to_as:            dict mapping IP to AS
    """

    guard_fp_to_res = {}

    # add innocent guards
    for guard in guard_list:
        if guard.address in ip_to_as:
            guard_as = ip_to_as[guard.address]
            guard_fp_to_res[guard.fingerprint] = guard_as_resiliences[guard_as]
        else:
            print("Error: cannot find guard IP in list of IP to AS")

    # add malicious guards
    for guard_fp, res in malicious_fp_to_res.items():
        guard_fp_to_res[guard_fp] = res

    return guard_fp_to_res


def make_guard_fp_to_bw(guard_to_bw, malicious_fp_to_bw):
    """
    Returns a dict mapping each guard FP to sum normalized bw

    guard_to_bw:        dict mapping innocent guards to bandwidth
    malicious_fp_to_bw: dict mapping malicious guard FPs to bandwidth
    """

    guard_fp_to_bw = {}

    # add innocent guards
    for guard, bw in guard_to_bw.items():
        guard_fp_to_bw[guard.fingerprint] = bw

    # add malicious guards
    for guard_fp, bw in malicious_fp_to_bw.items():
        guard_fp_to_bw[guard_fp] = bw

    # Use for Tille sampling (for sufficiently small values of g)
    sum_bw = sum(guard_fp_to_bw.values())
    return {fp: bw/sum_bw for (fp, bw) in guard_fp_to_bw.items()}



def compute_guard_weights(guard_fp_to_res, guard_fp_to_bw, alpha):
    """
    Returns a dict mapping guard fingerprint to CR weight

    guard_fp_to_res: dict mapping each guard AS to resilience (Tille sampled)
    guard_fp_to_bw:  dict mapping each guard FP to bandwidth (sum normalized)
    alpha:           alpha value for weighting
    """

    if len(guard_fp_to_res) != len(guard_fp_to_bw):
        print("Error: number of resiliences not equal to bandwidth")

    fp_to_weight = {}


    for fp, res in guard_fp_to_res.items():
        if fp in guard_fp_to_bw:
            bw_norm = guard_fp_to_bw[fp]
            weight = alpha * res + (1-alpha) * bw_norm

            fp_to_weight[fp] = weight
        else:
            print("Error: cannot find guard FP in guard bandwidths")

    return fp_to_weight

def compute_cr_guard_distr(client_as, 
                            best_as, 
                            client_to_all_res,
                            client_to_guard_res,
                            guard_to_bw, 
                            ip_to_as, 
                            num_relays, 
                            bw_resource,
                            alpha, 
                            sample_size):
    """
    ATTACK function (inserts optimal malicious guard)
    Returns a dict mapping each CR guard to its selection probability
    and the probability an adversary's guard is chosen

    client_as: target AS
    best_as: location of malicious guard(s)
    client_to_all_res: dict mapping clients to resiliences from all ASes
    client_to_guard_res: dict mapping clients to resiliences from innocent guard ASes
    guard_to_bw: dict mapping innocent guards to bandwidth
    ip_to_as: dict mapping IP to AS
    num_relays: number of malicious guards
    bw_resource: total adversary bandwidth resource
    alpha: alpha value for weighting
    sample_size: sample size for Tille sampling (set to 1 for no sampling)
    """

    best_res = client_to_all_res[client_as][best_as]

    malicious_fp_to_res = make_malicious_fp_to_res(num_relays, best_as, best_res)
    malicious_fp_to_bw = make_malicious_fp_to_bw(num_relays, best_as, bw_resource)

    guard_as_resiliences = client_to_guard_res[client_as]
    guard_list = list(guard_to_bw.keys())
    guard_fp_to_res = make_guard_fp_to_res(guard_as_resiliences,
                                        malicious_fp_to_res,
                                        guard_list,
                                        ip_to_as)

    # Tille sample resilience
    guard_fp_to_res_adj = adjust_resilience(guard_fp_to_res, sample_size)

    guard_fp_to_bw = make_guard_fp_to_bw(guard_to_bw, 
                                        malicious_fp_to_bw)
    
    fp_to_weight = compute_guard_weights(guard_fp_to_res_adj, guard_fp_to_bw, alpha)

    # compute distribution

    sum_weights = sum(fp_to_weight.values())
    # this should equal 1 if everything was sum-normalized    
    # print(f"sum_weights: {sum_weights}")

    guard_distr = {fp: weight/sum_weights for (fp, weight) in fp_to_weight.items()}

    succ_prob = sum([pr for (fp, pr) in guard_distr.items() if fp.startswith('AS')])

    return guard_distr, succ_prob


def compute_cr_selection_probs(client_as,
                                fp_to_bw,
                                fp_to_as,
                                client_to_all_res,
                                client_to_guard_res,
                                alpha,
                                sample_size):
    """
    Returns a dict mapping client AS to its Counter-RAPTOR guard
    selection probability, no malicious guard insertion.
    """

    print(f"ClientAS: {client_as}")

    bw_sum = sum(fp_to_bw.values())
    all_res = client_to_all_res[client_as]
    guard_res = client_to_guard_res[client_as]

    fp_to_res = {}
    for fp, asn in fp_to_as.items():

        if asn not in all_res:
            # if for some reason the guard ASes is not in list of all ASes
            print("Not in all_res")
            fp_to_res[fp] = guard_res[asn]

        else:
            fp_to_res[fp] = all_res[asn]

    if bw_sum == 0:
        # uniform distribute bandwidth if all guards have 0 bandwidth
        print("all bandwidths 0")
        fp_to_bw_norm = dict.fromkeys(fp_to_bw, 1/len(fp_to_bw))

    else:
        fp_to_bw_norm = {fp: bw/bw_sum for (fp, bw) in fp_to_bw.items()}
    
    if sum(fp_to_res.values()) == 0:
        # uniform distribute resilience if all guards have 0 resilience
        print("all resiliences 0")
        fp_to_res_adj = dict.fromkeys(fp_to_res, 1/len(fp_to_res))

    else:
        fp_to_res_adj = adjust_resilience(fp_to_res, sample_size)

    fp_to_weight = compute_guard_weights(fp_to_res_adj, 
                                    fp_to_bw_norm, 
                                    alpha)
    sum_weights = sum(fp_to_weight.values())
    selection_probs = {fp: weight/sum_weights for (fp, weight) in fp_to_weight.items()}

    print(f"sum weights: {sum(selection_probs.values())}")
    return selection_probs

