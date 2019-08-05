#!/usr/bin/env python3
"""
lastor.py
Author: Gerry Wan


"""

import os
import argparse
import pickle
import json
import re
import math
import operator
import copy
import geopy.distance
import geoip2.database

geoip_path = 'GeoLite2-City.mmdb'
guard_to_bw = pickle.load(open("../guard_info/guard_to_bw.pickle", "rb"))
fp_to_bw = {g.fingerprint: bw for (g, bw) in guard_to_bw.items()}
relay_ips = [ip.strip() for ip in open('../data/relay_ips.txt', 'r').readlines()]
client_to_all_clusters = json.load(open('../lastor/client_to_all_clusters.json'))

def get_ip_coord(ips_lst):
    """
    Returns a dict mapping IP address to {lat, lon} tuple.
    """

    reader = geoip2.database.Reader(geoip_path)

    ip_to_coord = {}
    for ip in ips_lst:
        response = reader.city(ip)
        lat = response.location.latitude
        lon = response.location.longitude
        if lat is None or lon is None:
            continue
        ip_to_coord[ip] = (float(lat), float(lon))

    reader.close()
    return ip_to_coord

def get_guard_coord(guard_to_bw):
    """
    Returns a dict mapping guard fingerprint to {lat, lon} tuple.
    """

    reader = geoip2.database.Reader(geoip_path)

    fp_to_coord = {}
    for guard, bw in guard_to_bw.items():
        ip = guard.address
        response = reader.city(ip)
        lat = response.location.latitude
        lon = response.location.longitude
        if lat is None or lon is None:
            continue
        fp_to_coord[guard.fingerprint] = (float(lat), float(lon))

    reader.close()
    return fp_to_coord

def get_cluster(lat, lon, edge=2):
    """
    Returns cluster index of lat,lon coordinate.
    """

    if lat > 90 or lat < -90 or lon > 180 or lon < -180:
        print("Error: lat/lon out of range.")
        return -1

    num_rows = int(180/edge)
    num_cols = int(360/edge)
    idx = int((lat - -90) // edge * num_cols + (lon - -180) // edge)

    return idx

def get_cluster_coord(idx, edge=2):
    """
    Returns (lat,lon) coordinates of center of cluster.
    """

    num_rows = int(180/edge)
    num_cols = int(360/edge)

    if idx >= num_rows*num_cols:
        print("Error: idx out of range.")
        return -1

    lat = -90 + (idx // num_cols) * edge + edge/2
    lon = -180 + (idx % num_cols) * edge + edge/2

    return (lat,lon)

def cluster(fp_to_coord, edge=2):
    """
    Returns a dict mapping cluster index to list of guard fingerprints
    in that cluster (only clusters with at least 1 guard)
    """    
    num_rows = int(180/edge)
    num_cols = int(360/edge)

    cluster_to_fp = {}

    for i in range(0, num_rows*num_cols):
        cluster_to_fp[i] = []

    for fp, coord in fp_to_coord.items():
        lat = coord[0]
        lon = coord[1]
        idx = get_cluster(lat, lon, edge)
        cluster_to_fp[idx].append(fp)

    cluster_to_fp = {k:v for k,v in cluster_to_fp.items() if len(v) > 0}
    return cluster_to_fp

def make_client_to_cluster_dist(client_lst):
    fp_to_coord = pickle.load(open("../guard_info/guard_fps_to_coord.pickle", "rb"))
    cluster_to_fp = cluster(fp_to_coord)

    client_to_cluster_dist = {}
    i = 0
    for client_coord in client_lst:
        cluster_to_dist = {}
        for idx, fps in cluster_to_fp.items():
            cluster_coord = get_cluster_coord(idx)
            dist = geopy.distance.distance(client_coord, cluster_coord).km
            cluster_to_dist[idx] = dist
        sorted_dists = dict(sorted(cluster_to_dist.items(), key=operator.itemgetter(1)))
        client_to_cluster_dist[i] = sorted_dists
        i += 1

    json.dump(client_to_cluster_dist, open("client_to_cluster_dist.json",'w'))

def compute_prob(client_coord, mal_guard_coord, mal_guard_bw, cluster_to_fp):
    """
    Returns the probability of target client selecting malicious guard,
    given that the malicious guard is placed at mal_guard_coord and has
    bandwidth mal_guard_bw.

    client_coord: (lat, lon) tuple for client location
    mal_guard_coord: (lat, lon) tuple for malicious guard location
    mal_guard_bw: malicious guard bandwidth
    cluster_to_fp: dict mapping cluster to guard fingerprints in that cluster
    """


    # choose closest g clusters (recommended 20%)
    g = 0.2

    mal_fp = "MALGUARD" 
    mal_cluster = get_cluster(mal_guard_coord[0], mal_guard_coord[1])

    new_cluster_to_fp = copy.deepcopy(cluster_to_fp)
    if mal_cluster in new_cluster_to_fp:
        new_cluster_to_fp[mal_cluster].append(mal_fp)
    else:
        new_cluster_to_fp[mal_cluster] = [mal_fp]

    all_clusters_dist = client_to_all_clusters[str(tuple(client_coord))]
    cluster_to_dist = {idx: all_clusters_dist[idx] for idx in new_cluster_to_fp}

    sorted_dists = sorted(cluster_to_dist.items(), key=operator.itemgetter(1))
    top_clusters = [i[0] for i in sorted_dists[: int(len(sorted_dists) * g)]]

    # if malicious guard is not in top 20% of clusters
    if mal_cluster not in top_clusters:
        # print("Not in top 20%")
        return 0, new_cluster_to_fp
    
    # use uniform random selection of cluster
    mal_cluster_prob = 1/len(top_clusters)


    num_guards_in_mal_cluster = len(new_cluster_to_fp[mal_cluster])

    mal_guard_prob = mal_cluster_prob * 1/num_guards_in_mal_cluster

    return mal_guard_prob, new_cluster_to_fp


def compute_untargeted_prob(client_lst, bw_resource, num_relays, outDir):
    """
    Returns the untargeted attack success probability for LASTor.
    *Computes the optimal attack locations using greedy algorithm*

    Reachable set is clusters containing at least one Tor relay.

    client_lst: list of (lat, lon) client geolocations
    bw_resource: total bandwidth resource of adversary
    num_relays: number of malicious guards

    if outDir is not None, dump to outDir/
    """


    mal_coords = list(get_ip_coord(relay_ips).values())
    bw = bw_resource / num_relays

    # initial state of guards
    fp_to_coord = pickle.load(open("../guard_info/guard_fps_to_coord.pickle", "rb"))
    cluster_to_fp = cluster(fp_to_coord)

    mal_guard_probs = {}
    for i in range(0, num_relays):
        cnt = 0
        # prob, mal_coord, cluster_to_fp, dist
        best_state = (0, (), {}, 1000000)  
        for mal_coord in mal_coords:

            sum_probs = 0
            for client_coord in client_lst:
                dist = geopy.distance.distance(client_coord, mal_coord).km

                prob, temp_cluster_to_fp = compute_prob(client_coord, 
                                                        mal_coord, 
                                                        bw, 
                                                        cluster_to_fp)

                sum_probs += prob

            avg_prob = sum_probs / len(client_lst)

            #print(cnt)
            cnt += 1
            if avg_prob > best_state[0]:
                best_state = (avg_prob, mal_coord, copy.deepcopy(temp_cluster_to_fp), dist)
            elif avg_prob == best_state[0] and dist < best_state[3]:
                best_state = (avg_prob, mal_coord, copy.deepcopy(temp_cluster_to_fp), dist)

        cluster_to_fp = copy.deepcopy(best_state[2])
        mal_guard_probs[str(best_state[1])] = best_state[0]
        if outDir is not None:
            json.dump(best_state, open(f"{outDir}/tempbeststate{i}.json", "w"))

    print(mal_guard_probs)
    if outDir is not None:
        json.dump(mal_guard_probs, open(f"{outDir}/malguardprobs.json", "w"))
    print(sum(mal_guard_probs.values()))
    
    return mal_guard_probs


def compute_lastor_guard_distr(client_coord, bw_resource):
    """
    ATTACK function (inserts optimal malicious guard)
    Returns a dict mapping each LASTor guard to its selection probability
    and the probability an adversary's guard is chosen (1 guard)

    client_coord: coordinate of client
    bw_resource: total bandwidth resource of adversary
    """

    mal_fp = 'MALGUARD'
    g = 0.2

    res = compute_untargeted_prob([client_coord], bw_resource, 1, None)
    
    for coord, prob in res.items():
        lat = float(coord[1:-1].split(',')[0])
        lon = float(coord[1:-1].split(',')[1])
    mal_coord = (lat, lon)
    mal_prob  = prob

    mal_cluster = get_cluster(mal_coord[0], mal_coord[1])

    fp_to_coord = pickle.load(open("../guard_info/guard_fps_to_coord.pickle", "rb"))
    cluster_to_fp = cluster(fp_to_coord)

    # add malicious guard to network
    if mal_cluster in cluster_to_fp:
        cluster_to_fp[mal_cluster].append(mal_fp)
    else:
        cluster_to_fp[mal_cluster] = [mal_fp]

    cluster_to_dist = {}
    for idx, fps in cluster_to_fp.items():
        cluster_coord = get_cluster_coord(idx)
        dist = geopy.distance.distance(client_coord, cluster_coord).km
        cluster_to_dist[idx] = dist

    sorted_dists = sorted(cluster_to_dist.items(), key=operator.itemgetter(1))
    top_clusters = [i[0] for i in sorted_dists[: int(len(sorted_dists) * g)]]

    all_guard_probs = {}
    for fp, coord in fp_to_coord.items():
        clust = get_cluster(coord[0], coord[1])
        if clust not in top_clusters:
            all_guard_probs[fp] = 0
        else:
            cluster_prob = 1/len(top_clusters)
            prob = cluster_prob * 1/len(cluster_to_fp[clust])
            all_guard_probs[fp] = prob

    all_guard_probs['MALGUARD'] = mal_prob
    return all_guard_probs


def compute_lt_selection_probs(client_coord,
                                fp_to_coord):
    """
    Returns a dict mapping client AS to its LASTor guard selection probability,
    no malicious guard insertion.
    """

    g = 0.2
    cluster_to_fp = cluster(fp_to_coord)

    cluster_to_dist = {}
    for idx, fps in cluster_to_fp.items():
        cluster_coord = get_cluster_coord(idx)
        dist = geopy.distance.distance(client_coord, cluster_coord).km
        cluster_to_dist[idx] = dist

    sorted_dists = sorted(cluster_to_dist.items(), key=operator.itemgetter(1))
    top_clusters = [i[0] for i in sorted_dists[: int(len(sorted_dists) * g)]]

    if len(top_clusters) == 0:
        selection_probs = dict.fromkeys(fp_to_coord, 1/len(fp_to_coord))
        return selection_probs

    selection_probs = {}
    for fp, coord in fp_to_coord.items():
        clust = get_cluster(coord[0], coord[1])
        if clust not in top_clusters:
            selection_probs[fp] = 0
        else:
            cluster_prob = 1/len(top_clusters)
            prob = cluster_prob * 1/len(cluster_to_fp[clust])
            selection_probs[fp] = prob

    return selection_probs

