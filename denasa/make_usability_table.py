#!/usr/bin/env python3
"""
make_usability_table.py
Author: Gerry Wan
"""

import denasa
import pfi
import json
import pickle

def main():
    """
    Makes top 368 clients to all guards usability table.
    """
    paths_filename = "as_paths.txt"
    index_filename = "as_paths_index.bin"
    libspookyhash_filename = "./libspookyhash.so"

    ip_to_as = json.load(open("../guard_info/ip_to_as.json"))
    guard_to_bw = pickle.load(open("../guard_info/guard_to_bw.pickle", "rb"))
    fp_to_as = {g.fingerprint: ip_to_as[g.address] for (g, bw) in guard_to_bw.items()}

    pfi_instance = pfi.PFI(libspookyhash_filename,
                    paths_filename,
                    index_filename)

    pfi_instance.load()
    pfi_instance.verify()

    client_as_lst = [asn.strip() for asn in open("../data/top368client.txt", 'r').readlines()]

    client_to_guard_usability = {}
    for client_as in client_as_lst:
        print(f'{client_as}')
        usability_table = denasa.make_guard_usability_dict(client_as, 
                                                            fp_to_as, 
                                                            pfi_instance)
        client_to_guard_usability[client_as] = usability_table

    json.dump(client_to_guard_usability, open("client_to_guard_usability.json", "w"))

if __name__ == "__main__":
    main()

