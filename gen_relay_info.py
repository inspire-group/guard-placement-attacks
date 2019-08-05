#!/usr/bin/env python3
"""
gen_relay_info.py
Author: Gerry Wan

Functions to generate relay and guard data
"""

import argparse
import relays
import json
import pickle
import geopy.distance
import geoip2.database

geoip_path = 'GeoLite2-City.mmdb'

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("ns_filename")
    return parser.parse_args()

def list_guard_ips(network_state):
    """ 
    generates text file that lists guard IP addresses for 
    use in Team-Cymru IP to AS mapping IP to AS mapping
    """
    guard_ips_outfile = "guard_info/guard_ips.txt"

    cons_rel_stats = network_state.cons_rel_stats
    descriptors = network_state.descriptors

    guard_list = relays.get_guard_list(cons_rel_stats, descriptors)
    print("Number of guards: %d" % len(guard_list))

    # guard IPs for IP-AS mapping
    file = open(guard_ips_outfile, 'w')
    file.write("begin\n")
    file.write("noasname\n")

    for guard in guard_list:
        file.write(guard.address)
        file.write('\n')
    file.write("end\n")

    file.close()
    print("Wrote to %s" % guard_ips_outfile)

def list_relay_ips(network_state):
    """ 
    generates text file that lists relay IP addresses for
    use in Team-Cymru IP to AS mapping
    """
    relay_ips_outfile = "data/relay_ips.txt"

    cons_rel_stats = network_state.cons_rel_stats
    descriptors = network_state.descriptors

    relay_list = relays.get_relay_list(cons_rel_stats)
    print("Number of relays: %d" % len(relay_list))

    # relay IPs for IP-AS mapping
    file = open(relay_ips_outfile, 'w')
    file.write("begin\n")
    file.write("noasname\n")

    for relay in relay_list:
        file.write(relay.address)
        file.write('\n')
    file.write("end\n")

    file.close()
    print("Wrote to %s" % relay_ips_outfile)

def list_guard_ases():
    """ 
    Takes Team-Cymru AS to IP mapping file as input.

    generates text file that lists all guard ASes
    *also generates json mapping guard IP to AS*
    """
    infile = open("data/cymru_as_to_ip_guards", 'r')
    guard_ases_outfile = "guard_info/guard_ases.txt"
    
    ases = set()
    ip_to_as = {}
    for line in infile:
        if '|' in line and 'NA' not in line:
            info = line.split('|')
            asn = info[0].strip()
            ip = info[1].strip()
            
            ases.add(asn)
            ip_to_as[ip] = asn
    infile.close()

    print("Num unique IPs: %d" % len(ip_to_as))
    print("Num ASes: %d" % len(ases))

    with open("guard_info/ip_to_as.json", 'w+') as file:
        json.dump(ip_to_as, file)
    print("Wrote to %s" % "guard_info/ip_to_as.json")

    file = open(guard_ases_outfile, 'w')
    for asn in ases:
        file.write(asn)
        file.write('\n')
    file.close()
    print("Wrote to %s" % guard_ases_outfile)

def list_relay_ases():
    """ 
    Takes Team-Cymru AS to IP mapping file as input.

    generates text file that lists all relay ASes
    """
    infile = open("data/cymru_as_to_ip_relays", 'r')
    list_of_ases_outfile = "data/relay_ases.txt"
    
    all_relay_ases = set()

    for line in infile:
        if '|' in line and 'NA' not in line:
            info = line.split('|')
            asn = info[0].strip()
            ip = info[1].strip()
            
            all_relay_ases.add(asn)
    infile.close()

    print("Num ASes: %d" % len(all_relay_ases))

    file = open(list_of_ases_outfile, 'w')
    for asn in all_relay_ases:
        file.write(asn)
        file.write('\n')
    file.close()
    print("Wrote to %s" % list_of_ases_outfile)

def main(args):

    print("Reading in network state: %s" % args.ns_filename)
    network_state = relays.tempest_fat_network_state(args.ns_filename)

    cons_rel_stats = network_state.cons_rel_stats
    descriptors = network_state.descriptors

    bw_weights = network_state.cons_bw_weights
    bwweightscale = network_state.cons_bwweightscale

    # Get list of guards from consensus
    guard_list = relays.get_guard_list(cons_rel_stats, descriptors)
    print(f"Num guards with appropriate flags: {len(guard_list)}")

    # outputs text files for Team-Cymru mappings
    list_guard_ips(network_state)
    list_relay_ips(network_state)

    list_guard_ases()
    list_relay_ases()

    ip_to_as = json.load(open("guard_info/ip_to_as.json"))
    print(f"Num unique IPs (one IP can host 2 guards): {len(ip_to_as)}")


    # Filter out guards with IPs not able to be mapped in CAIDA topology
    guard_list = [guard for guard in guard_list if guard.address in ip_to_as]
    print(f"Num guards CAIDA filtered: {len(guard_list)}")

    # Filter out guards with IPs not in Maxmind GeoIP database
    reader = geoip2.database.Reader(geoip_path)
    guard_list_geofilter = []
    for guard in guard_list:
        ip = guard.address
        response = reader.city(ip)
        lat = response.location.latitude
        lon = response.location.longitude
        if lat is not None and lon is not None:
            guard_list_geofilter.append(guard)

    guard_list = guard_list_geofilter
    print(f"Num guards Maxmind filtered: {len(guard_list)}")
    
    guard_to_bw = relays.get_guard_weights(guard_list, bw_weights, bwweightscale)

    # Filter out guards with 0 bandwidth
    guard_to_bw = {guard: bw for guard, bw in guard_to_bw.items() if bw > 0}
    print(f"Num guards 0 bw filtered: {len(guard_to_bw)}")

    print(f"Max guard bw: {max(guard_to_bw.values())}")
    print(f"Min guard bw: {min(guard_to_bw.values())}")
    print(f"Mean guard bw: {sum(guard_to_bw.values()) / len(guard_to_bw)}")


    
    pickle.dump(guard_to_bw, open("guard_info/guard_to_bw.pickle", "wb"))
    print("Wrote to %s" % "guard_info/guard_to_bw.pickle")
    


if __name__ == "__main__":
    main(parse_args())