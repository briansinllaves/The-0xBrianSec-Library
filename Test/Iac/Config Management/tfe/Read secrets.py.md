```
import requests

import os

print("Reading Secret from Test Vault Production...")

vault_headers = {

    "X-Vault-Token": "s.JtndB86fD.5rYuO",

    "X-Vault-nespace": "ifs/ptfee/ptfee-prd012/"

}

snow_secrect_response = requests.get("https://vault-us.testinternal.com:8200/v1/secret/data/snow_production", headers=vault_headers, verify=False)

snow_secrect_response.raise_for_status()

print(f"SNOW API Credentials: {snow_secrect_response.json()['data']['data']}")

print("Setting SNow APIM Credentials as Environment Variables")

snow_apim_credentials = snow_secrect_response.json()['data']['data']

os.environ["APIM_APIKEY"] = snow_apim_credentials["api_key"]

os.environ["APIM_APIKEYSECRET"] = snow_apim_credentials["api_key_secret"]

os.environ["APIM_AUTHORIZATION"] = snow_apim_credentials["auth"]

os.environ["APIM_PROXY_AUTHORIZATION"] = snow_apim_credentials["proxy_auth"]

print(f"API Credentials from EV: {os.environ['APIM_APIKEY']}")
```