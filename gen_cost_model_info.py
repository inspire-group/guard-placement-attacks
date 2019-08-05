#!/usr/bin/python3

import math

max_relays_per_ip = 2
def ips_for_relays(x):
    """Takes number of relays, return number of IP addresses needed."""
    return int(math.ceil(x/max_relays_per_ip))

# obtained from data/cost_model.xlsx
provider_costs = [
    {'name': 'OVH_vps',
    'bw_mbps': lambda x: 100/x,
    'max_ips': 16,
    'monthly_cost_usd': lambda x: (3.35+3*(ips_for_relays(x)-1))/x},
    {'name': 'OVH_dedicated',
    'bw_mbps': lambda x: 500/x,
    'max_ips': 16,
    'monthly_cost_usd': lambda x: (72+3*(ips_for_relays(x)-1))/x},
    {'name': 'Hetzner_dedicated',
    'bw_mbps': lambda x: 1000/x,
    'max_ips': None,
    'monthly_cost_usd': lambda x: (38.70+0.96*(ips_for_relays(x)-1))/x},
    {'name': 'Hetzner_cloud',
    'bw_mbps': lambda x: 61.73/x,
    'max_ips':  None,
    'monthly_cost_usd': lambda x: (2.85+1.14*(ips_for_relays(x)-1))/x},
    {'name': 'Online_SAS_dedicated',
    'bw_mbps': lambda x: 1000/x,
    'max_ips':  None,
    'monthly_cost_usd': lambda x: (11.40+2.28*(ips_for_relays(x)-1))/x},
    {'name': 'Online_SAS_cloud_xs',
    'bw_mbps': lambda x: 100/x,
    'max_ips':  None,
    'monthly_cost_usd': lambda x: (2.28+1.14*(ips_for_relays(x)-1))/x},
    {'name': 'Online_SAS_cloud_s',
    'bw_mbps': lambda x: 200/x,
    'max_ips':  None,
    'monthly_cost_usd': lambda x: (4.55+1.14*(ips_for_relays(x)-1))/x},
    {'name': 'Online_SAS_cloud_m',
    'bw_mbps': lambda x: 300/x,
    'max_ips':  None,
    'monthly_cost_usd': lambda x: (9.10+1.14*(ips_for_relays(x)-1))/x},
    {'name': 'Online_SAS_cloud_l',
    'bw_mbps': lambda x: 400/x,
    'max_ips':  None,
    'monthly_cost_usd': lambda x: (18.20+1.14*(ips_for_relays(x)-1))/x},
    {'name': 'Next_Layer_root',
    'bw_mbps': lambda x: 100,
    'max_ips': 1,
    'monthly_cost_usd':lambda x: 138.70},
    {'name': 'netcup_root',
    'bw_mbps': lambda x: 80,
    'max_ips': 1,
    'monthly_cost_usd': lambda x: 10.23},
    {'name': 'netcup_vps',
    'bw_mbps': lambda x: 123,
    'max_ips': 1,
    'monthly_cost_usd': lambda x: 3.07},
    {'name': 'myLoc_vps',
    'bw_mbps': lambda x: 300,
    'max_ips': 1,
    'monthly_cost_usd': lambda x: 11.37},
    {'name': 'myLoc_root',
    'bw_mbps': lambda x: 500,
    'max_ips': 1,
    'monthly_cost_usd': lambda x: 19.33},
    {'name': 'Digital_Ocean_standard',
    'bw_mbps': lambda x: 3/x,
    'max_ips': 4,
    'monthly_cost_usd':lambda x: 5/x},
]

if __name__ == '__main__':
    global_max_ips = 16 # would be an entire /24
    # compute for each product its costs-bandwidth pairs
    provider_cost_bws = []
    for provider_cost in provider_costs:
        if provider_cost['max_ips'] is None:
            max_ips = global_max_ips
        else:
            max_ips = provider_cost['max_ips']
        for num_relays in range(1, max_relays_per_ip*max_ips + 1):
            bw = provider_cost['bw_mbps'](num_relays)
            cost = provider_cost['monthly_cost_usd'](num_relays)
            provider_cost_bws.append((provider_cost['name'], bw, cost, num_relays))
    # find the minimum cost for each bandwidth
    bws_to_min_provider_costs = dict()
    for name, bw, cost, num_relays in provider_cost_bws:
        if bw not in bws_to_min_provider_costs:
            bws_to_min_provider_costs[bw] = (name, cost, num_relays)
        elif bws_to_min_provider_costs[bw][1] > cost:
            bws_to_min_provider_costs[bw] = (name, cost, num_relays)
    # make costs non-increasing in bandwidth
    bws_decreasing = sorted(bws_to_min_provider_costs.keys(), reverse=True)
    # min provider costs
    min_provider_costs = []
    cur_cost = None
    for bw in bws_decreasing:
        if (cur_cost is None):
            name, cost, num_relays = bws_to_min_provider_costs[bw]
            min_provider_costs.append((name, bw, cost, num_relays))
            cur_cost = bws_to_min_provider_costs[bw][1]
        else:
            name, cost, num_relays = bws_to_min_provider_costs[bw]
            if cost < cur_cost:
                min_provider_costs.append((name, bw, cost, num_relays))
                cur_cost = cost
    # print bandwidth costs
    print('Product\t\t\tNum relays\tBW (Mbps)\tMin cost ($/month)')
    for name, bw, cost, num_relays in min_provider_costs:
        print('{}\t{}\t\t{:.2f}\t\t{:.2f}'.format(name, num_relays, bw, cost))
    # print main logic of cost function
#    last_cost = None
#    for name, bw, cost, num_relays in min_provider_costs:
#        if last_cost is not None:
#            print('elif (bandwidth > {}):'.format(bw))
#            print('    cost = {}'.format(last_cost))
#        last_cost = cost
#    print('else:')
#    print('    cost = {}'.format(last_cost))
