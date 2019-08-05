#!/usr/bin/env python3
"""
gen_geoclient_data.py
Author: Gerry Wan

Generating geoclient coordinate datasets for LASTor analysis.
"""

import json
import csv

def gen_top_cities(num_clients):
    """
    Generates num_clients geoclients proportionally from the top 
    cities in the top countries that Tor users are from.
    """

    cities = {}
    with open('data/worldcities.csv', mode='r') as csv_file:
        csv_reader = csv.DictReader(csv_file)
        line_count = 0
        for row in csv_reader:
            if line_count == 0:
                print(f'Column names are {", ".join(row)}')
                line_count += 1
            else:
                city_id = row['id']
                city_ascii = row['city_ascii']
                lat = row['lat']
                lon = row['lng']
                country = row['country']
                population = row['population']
                if population == '':
                    population = 0
                else:
                    population = float(population)
                cities[city_id] = {'city':city_ascii, 'lat':lat, 'lon':lon, 'country':country, 'population':population}
                line_count += 1
        print(f'Processed {line_count} lines.')

    countries = {'United States': 0.2899,
                 'Russia': 0.2025,
                 'Germany': 0.1307,
                 'Indonesia': 0.0846,
                 'France': 0.0717,
                 'Ukraine': 0.0611,
                 'United Kingdom': 0.0499,
                 'India': 0.0442,
                 'Netherlands': 0.0358,
                 'Canada': 0.0296}

    top10 = {country: [] for country in countries}

    for city_id, data in cities.items():
        country = data['country']
        if country in top10.keys():
            top10[country].append(data)

    for country, frac in countries.items():
        n = round(frac * (num_clients+1))
        topfrac = sorted(top10[country], key=lambda k: k['population'])[-n:]
        top10[country] = topfrac

    geoclients = []
    for k,v in top10.items():
        for city in v:
            geoclients.append((float(city['lat']), float(city['lon'])))

    print(f'generated: {len(geoclients)}')
    json.dump(geoclients, open(f'data/geoclients{num_clients}.json','w'))
    

def gen_random_bbox(num_clients):
    """
    Generates num_clients geoclients randomly from within
    the bounding box of the top countries that Tor users are from.
    """

    bboxes = json.load(open("data/bound_boxes.json"))

    clients = []

    total_frac = 0
    for country, data in bboxes.items():
        total_frac += data[0]

    for country, data in bboxes.items():
        frac = data[0]/total_frac
        bbox = data[1]
        lo_lat = bbox[2]
        hi_lat = bbox[0]
        lo_lon = bbox[1]
        hi_lon = bbox[3]

        num_clients = round(frac * num_clients) 
        for i in range(0, num_clients):
            lat = round(random.uniform(lo_lat, hi_lat), 3)
            lon = round(random.uniform(lo_lon, hi_lon), 3)

            clients.append((lat, lon))

    print(len(clients))
    json.dump(clients, open(f'data/geoclients{num_clients}.json', 'w'))


    


