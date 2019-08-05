#!/usr/bin/env python3
"""
prefix_stats.py
Author: Gerry Wan


"""

import os
import argparse
import pickle
import json
import re
import math
import operator
import geopy.distance
import geoip2.database

geoip_path = 'GeoLite2-City.mmdb'

def get_24prefix_coords(ips_lst):
    """
    Returns a dict mapping IPv4 /24 prefixes to set of lat/lon locations.
    """
    reader = geoip2.database.Reader(geoip_path)

    pfx_coords = {}
    cnt = 0
    for ip in ips_lst:
        pfx = re.findall('.*\..*\..*\.', ip)[0]

        if pfx not in pfx_coords:
            coords = set()
        else:
            coords = pfx_coords[pfx]
        
        for i in range(0, 256):
            test_ip = pfx + str(i)
            response = reader.city(test_ip)
            lat = response.location.latitude
            lon = response.location.longitude
            coords.add((lat, lon))

        pfx_coords[pfx] = coords
        cnt += 1
        print(cnt)

    reader.close()
    return pfx_coords

def snap_to_corner(lat, lon, edge=2):
    """
    Returns (lat, lon) tuple of bottom left corner of cluster containing
    given lat, lon
    """

    new_lat = int(edge * math.floor(float(lat)/edge))
    new_lon = int(edge * math.floor(float(lon)/edge))
    return (new_lat, new_lon)

def get_24prefix_snapped(pfx_coords, edge=2):
    """
    Returns a dict mapping IPv4 /24 prefixes to set of lat/lon locations
    snapped to the bottom left corner of the cluster.

    pfx_coords: dict mapping /24 prefix to set of lat,lon pairs
    """
    snapped = {}

    for pfx, coords in pfx_coords.items():
        s = set()
        for coord in coords:
            if coord[0] is None or coord[1] is None:
                continue
            lat, lon = snap_to_corner(coord[0], coord[1], edge)
            s.add((lat, lon))
        snapped[pfx] = s

    return snapped

def print_24prefix_stats(pfx_coords, edge=2):
    """
    Prints stats about /24 prefixes containing Tor relays
    """

    snapped = get_24prefix_snapped(pfx_coords, edge)

    unique_coord_pfxs = 0
    unique_cluster_pfxs = 0
    max_coord_pfx = ("Unknown", 0)
    max_clusters_pfx = ("Unknown", 0)

    for k,v in pfx_coords.items():
        if len(v) > 1:
            unique_coord_pfxs += 1
        if len(v) > max_coord_pfx[1]:
            max_coord_pfx = (k, len(v))
        if len(snapped[k]) > 1:
            unique_cluster_pfxs += 1
        if len(snapped[k]) > max_clusters_pfx[1]:
            max_clusters_pfx = (k, len(snapped[k]))

    print(f"num prefixes with unique coords: {unique_coord_pfxs}")
    print(f"num prefixes with unique clusters: {unique_cluster_pfxs}")
    print(f"prefix with max unique coords: {max_coord_pfx}")
    print(f"prefix with max unique clusters: {max_clusters_pfx}")


def main():

    guard_to_bw = pickle.load(open("../guard_info/guard_to_bw.pickle", "rb"))
    pfxs = pickle.load(open("pfx_coords.pickle", "rb"))
    print_24prefix_stats(pfxs, 2)



if __name__ == "__main__":
    main()
