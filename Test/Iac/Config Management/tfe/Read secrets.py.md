```
import requests

import os

print("Reading Secret from Test Vault Production...")

vault_headers = {

    "X-Vault-Token": "s.",

    "X-Vault-nespace": "i/ptee/pe2/"

}

rain_secrect_response = requests.get("https://vault.internal.com:8200/v1/secret/data/sproduction", headers=vault_headers, verify=False)

rain_secrect_response.raise_for_status()

print(f"rain API Credentials: {rain_secrect_response.json()['data']['data']}")

print("Setting rain APIM Credentials as Environment Variables")

rain_apim_credentials = rain_secrect_response.json()['data']['data']

os.environ["APIM_APIKEY"] = rain_apim_credentials["api_key"]

os.environ["APIM_APIKEYSECRET"] = rain_apim_credentials["api_key_secret"]

os.environ["APIM_AUTHORIZATION"] = rain_apim_credentials["auth"]

os.environ["APIM_PROXY_AUTHORIZATION"] = rain_apim_credentials["proxy_auth"]

print(f"API Credentials from EV: {os.environ['APIM_APIKEY']}")
```