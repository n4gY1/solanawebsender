from solders.keypair import Keypair

import time
import random

import requests
import json
import jwt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import os
from time import time
import csv

_key_name = "organizations/"
_key_secret = "-----BEGIN EC PRIVATE KEY---"

USDC_UUID = "e05735c...."
EURC_UUID = "f19fec83...."



def get_account_uuid(key_name, key_secret,):
    request_method = "POST"
    url = "api.coinbase.com"
    request_path = "/v2/accounts/"
    jwt_payload = {
        'iss': 'cdp',
        'nbf': int(time()),
        'exp': int(time()) + 120,
        'sub': key_name,
        'uri': request_method + " " + url + request_path
    }

    # Generáljunk egy nonce-t
    nonce = os.urandom(16).hex()

    # Generáljuk a JWT-t
    jwt_token = jwt.encode(jwt_payload, key_secret, algorithm="ES256", headers={
        "kid": key_name,
        "nonce": nonce
    })
    print(jwt_token)

    # Fejlécek
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {jwt_token}"
    }
    response = requests.post(f"https://api.coinbase.com/v2/accounts", headers=headers)
    print(response.text)

def Usdc_sender(recipient, amount, key_name, key_secret, name):
    request_method = "POST"
    url = "api.coinbase.com"
    request_path = "/v2/accounts/{}/transactions".format(USDC_UUID)

    # JWT generálás
    jwt_payload = {
        'iss': 'cdp',
        'nbf': int(time()),
        'exp': int(time()) + 120,
        'sub': key_name,
        'uri': request_method + " " + url + request_path
    }

    # Generáljunk egy nonce-t
    nonce = os.urandom(16).hex()

    # Generáljuk a JWT-t
    jwt_token = jwt.encode(jwt_payload, key_secret, algorithm="ES256", headers={
        "kid": key_name,
        "nonce": nonce
    })

    # Fejlécek
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {jwt_token}"
    }

    # Kérés törzse
    body = {
        "type": "send",
        "to": str(recipient),
        "amount": str(amount),
        "currency": "USDC",
        "network": "solana",
        "travel_rule_data": {
            "is_self": "IS_SELF_TRUE",
            "beneficiary_name": name,
            "beneficiary_address": {"country": "HU"},
            "beneficiary_wallet_type": "WALLET_TYPE_SELF_HOSTED"
        }
    }

    # Kérés küldése
    response = requests.post(f"https://api.coinbase.com/v2/accounts/{USDC_UUID}/transactions", headers=headers,
                             data=json.dumps(body))

    # Válasz kezelése
    if response.status_code == 200:
        resp = response.json()
        transaction_id = resp['data']['id']
        destination_address = resp['data']['to']['address']
        when_create = resp['data']['created_at']
        amount = resp['data']['network']['transaction_amount']['amount']
        fee = resp['data']['network']['transaction_fee']['amount']
        with open('txlogs.csv', mode='a', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([transaction_id, destination_address, when_create, amount, fee])
    else:
        with open('txlogs.csv', mode='a', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(f"Error: {response.status_code}")
            with open(f'errlog_{recipient}.txt', 'w') as errorfile:
                errorfile.write(f'error:\n{response.text}')


def Eurc_sender(recipient, amount, key_name, key_secret, name):
    request_method = "POST"
    url = "api.coinbase.com"
    request_path = "/v2/accounts/{}/transactions".format(EURC_UUID)

    # JWT generálás
    jwt_payload = {
        'iss': 'cdp',
        'nbf': int(time()),
        'exp': int(time()) + 120,
        'sub': key_name,
        'uri': request_method + " " + url + request_path
    }

    # Generáljunk egy nonce-t
    nonce = os.urandom(16).hex()

    # Generáljuk a JWT-t
    jwt_token = jwt.encode(jwt_payload, key_secret, algorithm="ES256", headers={
        "kid": key_name,
        "nonce": nonce
    })

    # Fejlécek
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {jwt_token}"
    }

    # Kérés törzse
    body = {
        "type": "send",
        "to": str(recipient),
        "amount": str(amount),
        "currency": "EURC",
        "network": "solana",
        "travel_rule_data": {
            "is_self": "IS_SELF_TRUE",
            "beneficiary_name": name,
            "beneficiary_address": {"country": "HU"},
            "beneficiary_wallet_type": "WALLET_TYPE_SELF_HOSTED"
        }
    }

    # Kérés küldése
    response = requests.post(f"https://api.coinbase.com/v2/accounts/{EURC_UUID}/transactions", headers=headers,
                             data=json.dumps(body))

    # Válasz kezelése
    if response.status_code == 200:
        resp = response.json()
        transaction_id = resp['data']['id']
        destination_address = resp['data']['to']['address']
        when_create = resp['data']['created_at']
        amount = resp['data']['network']['transaction_amount']['amount']
        fee = resp['data']['network']['transaction_fee']['amount']
        with open('txlogs.csv', mode='a', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([transaction_id, destination_address, when_create, amount, fee])
    else:
        with open('txlogs.csv', mode='a', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(f"Error: {response.status_code}")
            with open(f'errlog_{recipient}.txt', 'w') as errorfile:
                errorfile.write(f'error:\n{response.text}')


def send_from_wallets(wallets, key_name, key_secret, name):
    log = {}
    key_secret = key_secret.replace('\\n', '\n')
    get_account_uuid(key_name,key_secret)

    for wallet in wallets.split("\r\n"):
        base58_string = wallet

        try:
            pubkey = Keypair.from_base58_string(base58_string).pubkey()
            recipient = pubkey


            print(pubkey)
            print(recipient)
            print(key_name)
            print(key_secret)
            print(name)

            usdc_amount = round(random.uniform(1, 1.79), 2)
            eurc_amount = round(random.uniform(0.15, 0.65), 2)

            Eurc_sender(recipient=recipient, amount=eurc_amount, key_name=key_name, key_secret=key_secret, name=name)
            #wait_time = round(random.uniform(10, 49))  # meghatározza a várakozási időt a következő iteráció előtt
            #time.sleep(wait_time)  #várakozik a következő utalás előtt

            #Usdc_sender(recipient=recipient, amount=usdc_amount, key_name=key_name, key_secret=key_secret, name=name)
            #wait_time = round(random.uniform(22, 78))  #meghatározza a várakozási időt a következő iteráció előtt
            print("nincs hiba, várakozik")
            #time.sleep(wait_time)  #várakozik a következő iteráció előtt

        except ValueError as e:
            print(f"Hiba történt: {e}")
