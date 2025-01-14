import base64
import time

import jwt
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from solders.keypair import Keypair

import random

import requests
import json

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

import time
import secrets
import http.client
import json
import os

import csv

_key_name = "organizations/"
_key_secret = "-----BEGIN EC PRIVATE KEY---"

USDC_UUID = "e05735c...."
EURC_UUID = "f19fec83...."


def get_account_uuid(key_name, key_secret, currency):
    request_method = "GET"
    request_host = "api.coinbase.com"
    request_path = "/api/v3/brokerage/accounts/"
    token = ""
    uri = f"{request_method} {request_host}{request_path}"

    private_key_bytes = key_secret.encode('utf-8')
    private_key = load_pem_private_key(private_key_bytes, password=None)
    jwt_payload = {
        'sub': key_name,
        'iss': "cdp",
        'nbf': int(time.time()),
        'exp': int(time.time()) + 120,
        'uri': uri,
    }
    jwt_token = jwt.encode(
        jwt_payload,
        private_key,
        algorithm='ES256',
        headers={'kid': key_name, 'nonce': secrets.token_hex()},
    )

    uri = f"{request_method} {request_host}{request_path}"

    conn = http.client.HTTPSConnection(request_host)
    headers = {
        'Authorization': f"Bearer {jwt_token}",
        'Content-Type': 'application/json'
    }
    conn.request("GET", request_path, '', headers)
    res = conn.getresponse()
    data = res.read()
    data.decode("utf-8")
    json_data = json.loads(data.decode("utf-8"))
    for wallet in json_data["accounts"]:
        if wallet["currency"] == currency:
            print(wallet)
            return wallet["uuid"]
    return None


"""
def usdc_sender(recipient, amount, key_name, key_secret, name, wallett_uuid):
    request_method = "POST"
    url = "api.coinbase.com"
    request_path = "/v2/accounts/{}/transactions".format(wallett_uuid)

    # JWT generálás
    jwt_payload = {
        'iss': 'cdp',
        'nbf': int(time.time()),
        'exp': int(time.time()) + 120,
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

"""


def coinbase_sender(recipient, amount, key_name, key_secret, name, wallet_uuid, currency):
    request_method = "POST"
    url = "api.coinbase.com"
    request_path = "/v2/accounts/{0}/transactions".format(wallet_uuid)

    # JWT generálás
    jwt_payload = {
        'iss': 'cdp',
        'nbf': int(time.time()),
        'exp': int(time.time()) + 120,
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
        "currency": currency,
        "network": "solana",
        "travel_rule_data": {
            "is_self": "IS_SELF_TRUE",
            "beneficiary_name": name,
            "beneficiary_address": {"country": "HU"},
            "beneficiary_wallet_type": "WALLET_TYPE_SELF_HOSTED"
        }
    }

    # Kérés küldése
    response = requests.post(f"https://api.coinbase.com/v2/accounts/{wallet_uuid}/transactions", headers=headers,
                             data=json.dumps(body))

    # Válasz kezelése
    if response.status_code == 200:
        resp = response.json()
        transaction_id = resp['data']['id']
        destination_address = resp['data']['to']['address']
        when_create = resp['data']['created_at']
        amount = resp['data']['network']['transaction_amount']['amount']
        fee = resp['data']['network']['transaction_fee']['amount']
        print(fee)

        return {
            "fee": fee,
            "transaction_id": transaction_id,
            "destination_address": destination_address,
            "when_create": when_create,
            "amount": amount
        }

    else:
        with open('txlogs.csv', mode='a', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(f"Error: {response.status_code}")
            with open(f'errlog_{recipient}.txt', 'w') as errorfile:
                errorfile.write(f'error:\n{response.text}')


def send_from_wallets(wallets, key_name, key_secret, name):
    log = []
    key_secret = key_secret.replace('\\n', '\n')

    usdc_uuid = get_account_uuid(key_name, key_secret, "USDC")
    eurc_uuid = get_account_uuid(key_name, key_secret, "EURC")

    if usdc_uuid is None or eurc_uuid is None:
        return 0

    for wallet in wallets.split("\r\n"):
        base58_string = wallet

        try:
            pubkey = Keypair.from_base58_string(base58_string).pubkey()
            recipient = pubkey

            #print(recipient)
            #print(key_name)
            #print(key_secret)
            #print(name)

            usdc_amount = round(random.uniform(1, 1.20), 2)
            eurc_amount = round(random.uniform(0.10, 0.25), 2)

            logger_eurc = coinbase_sender(recipient=recipient, amount=eurc_amount, key_name=key_name,
                                          key_secret=key_secret,
                                          name=name, wallet_uuid=eurc_uuid, currency="EURC")

            logger_usdc = coinbase_sender(recipient=recipient, amount=usdc_amount, key_name=key_name,
                                          key_secret=key_secret,
                                          name=name, wallet_uuid=usdc_uuid, currency="USDC")

            log.append(logger_eurc)
            log.append(logger_usdc)
            if logger_eurc.get("fee") != "0" or logger_usdc.get("fee") != "0":
                print("!", logger_usdc.get("fee"), logger_usdc.get("fee"))
                return log

            #wait_time = round(random.uniform(10, 49))  # meghatározza a várakozási időt a következő iteráció előtt
            #time.sleep(wait_time)  #várakozik a következő utalás előtt

            #Usdc_sender(recipient=recipient, amount=usdc_amount, key_name=key_name, key_secret=key_secret, name=name)
            #wait_time = round(random.uniform(22, 78))  #meghatározza a várakozási időt a következő iteráció előtt

            #time.sleep(wait_time)  #várakozik a következő iteráció előtt
        except Exception as e:
            print("[!] ERROR", str(e))
    return log
