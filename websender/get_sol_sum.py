import json

import requests


def get_solana_sum(wallets):
    url = "https://api.mainnet-beta.solana.com"

    headers = {
        "Content-Type": "application/json"
    }

    total_sol = 0
    pk=0

    for data in wallets.split("\r\n"):

        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getBalance",
            "params": [data]
        }
        response = requests.post(url, headers=headers, data=json.dumps(payload))
        data = response.json()
        lamports = data.get("result", {}).get("value", 0)
        sol_balance = lamports / 1e9
        pk += 1
        total_sol += sol_balance


    return total_sol
