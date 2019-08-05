#!/usr/bin/env python3
# -*- coding: utf-8 -*-
##################################################
# counter_raptor_resilience.py
# compute resilience value for given client and guard sets
# Input:
# List of Tor client ASes (--client_file, default="../data/top400client.txt")
# List of Tor guard ASes (--guard_as_file, default="../data/as_guard.txt")
# CAIDA AS topology (--topology_file, default="../data/20161001.as-rel2.txt")
# Output:
# Tor client to guard resiliences (cg_resilience.json)
##################################################


import sys
import json
import time
from collections import deque
import argparse
from copy import deepcopy


# graph format: graph[node] = [weight, equal_paths, uphill_hops]
# initialize graph
def init(root):
    global graph
    graph = {}
    graph[root] = [0,1,0]

# provider to customer
def bfs_pc(q_lst):
    global graph, asdict
    q = deque(q_lst)
    while q:
        current = q.popleft()
        val = graph[current]
        for node in asdict[current][0]:
            if node not in graph:
                graph[node] = [val[0] + 1, val[1], val[2]]
                q.append(node)
            elif graph[node][0] == val[0] + 1:
                graph[node][1] += val[1]

# peer to peer
def bfs_pp(q_lst):
    global graph, asdict, total_as
    q = deque()
    for rt in q_lst:
        for node in asdict[rt][1]:
            if node not in graph:
                graph[node] = [graph[rt][0] + total_as, graph[rt][1], graph[rt][2]]
                q.append(node)
            elif graph[node][0] == graph[rt][0] + total_as:
                graph[node][1] += graph[rt][1]
    while q:
        current = q.popleft()
        val = graph[current]
        for node in asdict[current][0]:
            if node not in graph:
                graph[node] = [val[0] + 1, val[1], val[2]]
                q.append(node)
            elif graph[node][0] == val[0] + 1:
                graph[node][1] += val[1]

# customer to provider
def bfs_cp(root):
    global graph, asdict
    q = deque([root])
    curlst = []
    curlevel = 0
    while q:
        current = q.popleft()
        val = graph[current]
        if val[2] > curlevel:
            bfs_pc(curlst)
            bfs_pp(curlst)
            curlst = []
            curlevel = val[2]
        for node in asdict[current][2]:
            if node not in graph:
                graph[node] = [val[0], val[1], val[2] + 1]
                q.append(node)
                curlst.append(node)
            elif graph[node][2] == (val[2]+1):
                graph[node][1] += val[1]

# traverse nodes to calculate resiliency
def update_resilience():
    global graph, tordict, total_as
    L = sorted(list(graph.items()), key=lambda k_v: (-k_v[1][2],-k_v[1][0]))
    L2 = [k_v1[0] for k_v1 in L]
    #print L2
    unreachable = total_as - 1 - len(L2)
    #print "number of unreachable nodes is %i" % unreachable
    nodes = 0
    prev = ()
    eq_path = 0
    eq_nodes = 0
    buffer = []
    for item in L2:
        val = graph[item]
        if prev==(val[0],val[2]):
            eq_path += val[1]
            eq_nodes += 1
            if item in tordict:
                buffer.append((item,val[1]))
        else:
            for node in buffer:
                tordict[node[0]] += nodes + unreachable + ((node[1] / eq_path) if eq_nodes > 1 else 0)
            buffer = []
            nodes += eq_nodes
            eq_path = val[1]
            eq_nodes = 1
            prev = (val[0],val[2])
            if item in tordict:
                buffer = [(item,val[1])]
    # leftover nodes in buffer
    for node in buffer:
        tordict[node[0]] += nodes + unreachable + ((node[1] / eq_path) if eq_nodes > 1 else 0)

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--topology_file",
                        default="../data/20180801.as-rel2.txt")
    parser.add_argument("--client_file",
                        default="../data/top368client.txt")
    parser.add_argument("--guard_as_file",
                        default="../guard_info/guard_ases.txt")
    parser.add_argument("--out_file",
                        default="cg_resilience.json")
    return parser.parse_args()

def main(args):
    global asdict, tordict, graph, total_as
    asdict = {}
    tordict = {}

    # load AS relationships from CAIDA topo file
    # asdict[asn] = [[provider-customer edges],[peer-to-peer edges],[customer-provider edges]]
    for line in open(args.topology_file):
        if not line.strip().startswith("#"):
            arr = line.strip().split('|')
            asn1 = arr[0]
            asn2 = arr[1]
            rel = int(arr[2]) # -1: provider-customer; 0: peer-to-peer
            if asn1 in asdict:
                asdict[asn1][rel+1].append(asn2)
            else:
                asdict[asn1] = [[],[],[]]
                asdict[asn1][rel+1] = [asn2]
            if asn2 in asdict:
                asdict[asn2][abs(rel)+1].append(asn1)
            else:
                asdict[asn2] = [[],[],[]]
                asdict[asn2][abs(rel)+1] = [asn1]

    for line in open(args.guard_as_file):
        tordict[line.strip()] = 0

    total_as = len(asdict)
    print("%d ASes found in topology and %d Tor ASes" % (total_as, len(tordict)))

    # sys.exit(0)

    # start caculation per client
    client_dict = {}
    start = time.time()

    for line in open(args.client_file):
        item = line.strip()
        if not item in asdict:
            print("sorry we cannot find the client asn %s" % item)
        else:
            init(item)
            bfs_pc([item])
            bfs_pp([item])
            bfs_cp(item)
            graph.pop(item,None)
            update_resilience()
            for el in tordict:
                tordict[el] = tordict[el] / (total_as - 2)
            if sum(tordict.values()) == 0:
                print("%s client have all 0 values" % item)
            client_dict[item] = deepcopy(tordict)
            tordict = dict.fromkeys(tordict, 0)

    end = time.time()
    print(end - start)

    outfile = args.out_file
    with open(outfile, 'w+') as fp:
        json.dump(client_dict, fp)


if __name__ == '__main__':
    main(parse_args())

