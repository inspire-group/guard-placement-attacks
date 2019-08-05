#!/usr/bin/env python3
"""
make_distance_table.py
Author: Gerry Wan

Creates client_to_all_clusters and client_to_guard_dist_200 tables.
"""

import lastor
import geopy.distance
import geoip2.database

import json
import pickle


def make_client_to_clusters():
    """
    Makes top 200 clients to all clusters distance table.
    """

    geoip_path = 'GeoLite2-City.mmdb'

    fp_to_coord = pickle.load(open("../guard_info/guard_fps_to_coord.pickle", "rb"))

    client_coord_lst = json.load(open('../data/geoclients200.json', 'r'))

    client_to_guard_dist = {}
    cnt = 0
    for client_coord in client_coord_lst:
        print(f'{client_coord}')
        print(cnt)
        cnt += 1

        cluster_dists = []
        for i in range(0, 16200):
            cluster_coord = lastor.get_cluster_coord(i, 2)
            dist = geopy.distance.distance(client_coord, cluster_coord).km
            cluster_dists.append(dist)
        client_to_guard_dist[str(tuple(client_coord))] = cluster_dists

    json.dump(client_to_guard_dist, open("client_to_all_clusters.json", "w"))

def make_client_to_guards():
    """
    Makes top 200 clients to all guards distance table.
    """

    geoip_path = 'GeoLite2-City.mmdb'

    fp_to_coord = pickle.load(open("../guard_info/guard_fps_to_coord.pickle", "rb"))

    client_coord_lst = json.load(open('../data/geoclients200.json', 'r'))

    client_to_guard_dist = {}
    for client_coord in client_coord_lst:
        print(f'{client_coord}')
        dist_table = {}
        for fp, coord in fp_to_coord.items():
            lat = coord[0]
            lon = coord[1]
            dist = geopy.distance.distance(client_coord, (lat,lon)).km
            dist_table[fp] = dist
        client_to_guard_dist[str(tuple(client_coord))] = dist_table

    json.dump(client_to_guard_dist, open("client_to_guard_dist_200.json", "w"))

def main():
    make_client_to_guards()

if __name__ == "__main__":
    main()

