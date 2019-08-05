#!/usr/bin/env python3
"""
relays.py
Author: Gerry Wan

Functions to grab relays and weights from Tor consensus files.
"""

import argparse
import datetime
from io import BytesIO
import ipaddress
import pickle
import re
import math

from stem import Flag
import stem.descriptor

DEFAULT_BWWEIGHTSCALE = 10000

# Modified from torps pathsim
class NetworkState:
    """
    Contains slimmed down version of Tor network state in a consensus period.
    """
    
    def __init__(self, cons_rel_stats, descriptors, cons_valid_after,
        cons_fresh_until, cons_bw_weights, cons_bwweightscale):
        self.cons_rel_stats = cons_rel_stats
        self.descriptors = descriptors
        self.cons_valid_after = cons_valid_after
        self.cons_fresh_until = cons_fresh_until
        self.cons_bw_weights = cons_bw_weights
        self.cons_bwweightscale = cons_bwweightscale


# Grabbed from torps pathsim
def pathsim_timestamp(t):
    """
    Returns UNIX timestamp
    """
    td = t - datetime.datetime(1970, 1, 1)
    ts = td.days*24*60*60 + td.seconds
    return ts


def get_relay_list(cons_rel_stats):
    """
    Returns all relays in consensus
    """

    return list(cons_rel_stats.values())


# Modified from torps pathsim.py
def get_guard_list(cons_rel_stats, descriptors):
    """
    Returns relays filtered by general (non-client-specific) guard criteria.
    In particular, omits checks for IP/family/subnet conflicts within list. 
    """

    guards = []

    for fprint in cons_rel_stats:
        rel_stat = cons_rel_stats[fprint]
        if ((Flag.RUNNING in rel_stat.flags) 
            and (Flag.VALID in rel_stat.flags) 
            and (Flag.GUARD in rel_stat.flags) 
            and (Flag.FAST in rel_stat.flags)
            and (Flag.STABLE in rel_stat.flags)
            and (Flag.V2DIR in rel_stat.flags)
            and (fprint in descriptors)):
            guards.append(rel_stat)

    return guards
    

# Modified from torps pathsim.py
def get_guard_weights(guard_list, bw_weights, bwweightscale):
    """Returns un-normalized bandwidth for each guard in guard_list"""

    guards_to_bw_weight = {}
    for guard in guard_list:
        bw = float(guard.bandwidth)
        weight = (float(pathsim_get_bw_weight(guard.flags,'g', bw_weights)) /
                  float(bwweightscale))
        bw_weight = bw * weight

        guards_to_bw_weight[guard] = bw_weight

    return guards_to_bw_weight

    
# Grabbed from torps pathsim.py
def pathsim_get_bw_weight(flags, position, bw_weights):
    """Returns weight to apply to relay's bandwidth for given position.  flags:
        list of Flag values for relay from a consensus position: position for
        which to find selection weight, one of 'g' for guard, 'm' for middle,
        and 'e' for exit bw_weights: bandwidth_weights from
        NetworkStatusDocumentV3 consensus """

    if (position == 'g'):
        if (Flag.GUARD in flags) and (Flag.EXIT in flags):
            return bw_weights['Wgd']
        elif (Flag.GUARD in flags):
            return bw_weights['Wgg']
        elif (Flag.EXIT not in flags):
            return bw_weights['Wgm']
        else:
            raise ValueError('Wge weight does not exist.')
    else:
        raise NotImplementedError()


# Modified from tempest relays.py
def tempest_fat_network_state(ns_filename):
    """Reading fat network state file into commonly-used variables.
    Cannot use pathsim.get_network_state() because nsf is fat."""
    cons_rel_stats = {}
    with open(ns_filename, 'rb') as nsf:
        consensus_str = pickle.load(nsf, encoding='bytes')
        # convert consensus from string to stem object
        i = 0
        for doc in stem.descriptor.parse_file(BytesIO(consensus_str),
                                              validate=True,
                                              document_handler='DOCUMENT'):
            if (i > 0):
                raise ValueError('Unexpectedly found more than one consensus in network state file')
            consensus = doc
            i += 1
        # convert descriptors from strings to stem objets
        descriptors = pickle.load(nsf, encoding='bytes')
        for fprint, desc_str in descriptors.items():
            i = 0
            for desc in stem.descriptor.parse_file(BytesIO(desc_str), validate = True):
                if (i > 0):
                    raise ValueError('Unexpectedly found more than one descriptor in dict entry')
                descriptors[fprint] = desc
                i += 1
        hibernating_statuses = pickle.load(nsf, encoding='bytes')

    # descriptor conversion
    converted_descriptors = {}
    for fprint, descriptor in descriptors.items():
        converted_descriptors[fprint.decode('utf-8')] = descriptor

    descriptors = converted_descriptors

    # set variables from consensus
    cons_valid_after = pathsim_timestamp(consensus.valid_after)
    cons_fresh_until = pathsim_timestamp(consensus.fresh_until)
    cons_bw_weights = consensus.bandwidth_weights
    if ('bwweightscale' not in consensus.params):
        cons_bwweightscale = DEFAULT_BWWEIGHTSCALE
    else:
        cons_bwweightscale = consensus.params['bwweightscale']
    for relay_fprint in consensus.routers:
        if (relay_fprint in descriptors):
            cons_rel_stats[relay_fprint] = consensus.routers[relay_fprint]

    return NetworkState(cons_rel_stats, descriptors, cons_valid_after, cons_fresh_until, cons_bw_weights, cons_bwweightscale)


def get_real_bw(bandwidth_weight):
    """
    Returns real bandwidth in Bytes/second given bandwidth weight 
    (from linear regression).
    """

    # from generate_real_bw_info.py
    slope = 763.80
    intercept = 2098271.21

    return bandwidth_weight * slope + intercept

def relay_cost(bandwidth):
    """
    Empirical cost model (developed by Aaron Johnson).
    """
    if (bandwidth >= 1000):
        cost = 11.4 * math.ceil(bandwidth/1000)
    elif (bandwidth > 500.0):
        cost = 11.4
    elif (bandwidth > 333.3333333333333):
        cost = 5.7
    elif (bandwidth > 250.0):
        cost = 4.56
    elif (bandwidth > 200.0):
        cost = 3.42
    elif (bandwidth > 166.66666666666666):
        cost = 3.192
    elif (bandwidth > 142.85714285714286):
        cost = 2.66
    elif (bandwidth > 125.0):
        cost = 2.605714285714286
    elif (bandwidth > 111.11111111111111):
        cost = 2.2800000000000002
    elif (bandwidth > 100.0):
        cost = 2.28
    elif (bandwidth > 83.33333333333333):
        cost = 2.052
    elif (bandwidth > 71.42857142857143):
        cost = 1.8999999999999997
    elif (bandwidth > 62.5):
        cost = 1.7914285714285714
    elif (bandwidth > 55.55555555555556):
        cost = 1.71
    elif (bandwidth > 50.0):
        cost = 1.6466666666666667
    elif (bandwidth > 33.333333333333336):
        cost = 1.14
    elif (bandwidth > 25.0):
        cost = 1.1383333333333334
    elif (bandwidth > 16.666666666666668):
        cost = 0.855
    elif (bandwidth > 12.5):
        cost = 0.7599999999999999
    elif (bandwidth > 10.0):
        cost = 0.7124999999999999
    elif (bandwidth > 8.333333333333334):
        cost = 0.6839999999999999
    elif (bandwidth > 7.142857142857143):
        cost = 0.6649999999999999
    elif (bandwidth > 6.25):
        cost = 0.6514285714285714
    elif (bandwidth > 5.555555555555555):
        cost = 0.64125
    elif (bandwidth > 5.0):
        cost = 0.6333333333333333
    elif (bandwidth > 4.545454545454546):
        cost = 0.627
    elif (bandwidth > 4.166666666666667):
        cost = 0.6218181818181817
    elif (bandwidth > 3.8461538461538463):
        cost = 0.6174999999999999
    elif (bandwidth > 3.5714285714285716):
        cost = 0.6138461538461538
    elif (bandwidth > 3.3333333333333335):
        cost = 0.6107142857142857
    elif (bandwidth > 3.125):
        cost = 0.608
    else:
        cost = 0.605625
    return cost

def get_cost(bandwidth_weight):
    """
    Returns monetary cost in US dollars of deploying a relay 
    for 1 month given bandwidth weight.
    """

    real_bw_Bps = get_real_bw(bandwidth_weight)
    real_bw_Mbps = (real_bw_Bps * 8) / 1e6
    return relay_cost(real_bw_Mbps)