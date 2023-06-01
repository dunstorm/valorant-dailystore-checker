import requests
from collections import OrderedDict
from requests.adapters import HTTPAdapter
from typing import Any
import ssl
from constants import CIPHERS, RIOTCLIENT, AUTH_URL
import argparse
import re
import os
from datetime import datetime, timedelta
import json

class SSLAdapter(HTTPAdapter):
	def init_poolmanager(self, *a: Any, **k: Any) -> None:
		c = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
		c.set_ciphers(':'.join(CIPHERS))
		k['ssl_context'] = c
		return super(SSLAdapter, self).init_poolmanager(*a, **k)

def extract_token_from_text(text: str):
    regex = r"access_token=(.*?)&"
    matches = re.findall(regex, str(text))
    if matches:
        return matches[0]
    else:
        print('No token found in text: {}'.format(text))
        exit()

class ValorantClient:
    def __init__(self, username: str, password: str, region: str = 'ap'):
        self.username = username
        self.password = password
        self.access_token = None
        self.region = region
        self.entitlements_token = None
        self.sub_id = None

        self.user_agent = f'RiotClient/{RIOTCLIENT} %s (Windows;10;;Professional, x64)'
        headers = OrderedDict({
            "Accept-Language": "en-US,en;q=0.9",
            "Accept": "application/json, text/plain, */*",
            'User-Agent': self.user_agent
        })
        self.s = requests.Session()
        self.s.headers = headers
        self.s.mount('https://', SSLAdapter())
          
    def login(self):
        # save the response to a file in accounts/ folder
        # create folder if it doesn't exist
        # folder path is same as the path of this script
        accounts_folder = os.path.join(os.path.dirname(__file__), 'accounts')
        if not os.path.exists(accounts_folder):
            os.makedirs(accounts_folder)
        username_file_path = os.path.join(accounts_folder, f'{self.username}.json')

        # check if the file exists
        if os.path.exists(username_file_path):
            with open(username_file_path, 'r') as f:
                data = f.read()
                if len(data) > 0:
                    # check expires_at 
                    if datetime.fromisoformat(json.loads(data)['expires_at']) > datetime.now():
                        print('Token: Valid')
                        # still valid
                        self.access_token = extract_token_from_text(data)
                        return

        data = {
            "acr_values": "urn:riot:bronze",
            "claims": "",
            "client_id": "riot-client",
            "nonce": "oYnVwCSrlS5IHKh7iI16oQ",
            "redirect_uri": "http://localhost/redirect",
            "response_type": "token id_token",
            "scope": "openid link ban lol_region"
        }
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': self.user_agent
        }

        try:
            self.s.post(AUTH_URL, json=data, headers=headers, timeout=20)
            data = {
                'type': 'auth',
                'username': self.username,
                'password': self.password
            }
            r2 = self.s.put(AUTH_URL, json=data, headers=headers, timeout=20)
            r2.raise_for_status()
            # {"type":"response","response":{"mode":"fragment","parameters":{"uri":"http://localhost/redirect#access_token={x}&scope=openid+link+ban+lol_region+lol+summoner+offline_access&iss=https%3A%2F%2Fauth.riotgames.com&id_token={x}&token_type=Bearer&session_state={x}&expires_in=3600"}},"country":"x"}
            # extract access token from response using regex
            self.access_token = extract_token_from_text(r2.text)

            # save the response to a file
            with open(username_file_path, 'w') as f:
                save_json = r2.json()
                save_json['expires_at'] = (datetime.now() + timedelta(seconds=3600)).isoformat()
                f.write(json.dumps(save_json))

            print('Token: Saved')
            return
        except Exception as e:
            print('Error: ', e)
            exit()

    def get_entitlements_token(self):
        '''
        curl -X POST 'https://entitlements.auth.riotgames.com/api/token/v1' \
            -H 'Authorization: Bearer {x}' \
            -H 'User-Agent: RiotClient/58.0.0.4640299.4552318 rso-auth (Windows;10;;Professional, x64)' \
            -H 'Content-Type: application/json;charset=UTF-8' \
            -d '{}' \
            --compressed
        '''
        try:
            r = self.s.post(
                'https://entitlements.auth.riotgames.com/api/token/v1',
                headers={
                    'Authorization': f'Bearer {self.access_token}',
                    'User-Agent': self.user_agent
                },
                json={}
            )
            r.raise_for_status()
            self.entitlements_token = r.json()['entitlements_token']
        except Exception as e:
            print('Error fetching entitlements token:', e)
            exit()

    def get_sub_id(self):
        '''
        curl -X POST 'https://auth.riotgames.com/userinfo' \
            -H 'Authorization: Bearer {x}' \
            -H 'User-Agent: RiotClient/58.0.0.4640299.4552318 rso-auth (Windows;10;;Professional, x64)' \
            -H 'Content-Type: application/json;charset=UTF-8' \
            -d '{}' \
            --compressed
        '''
        try:
            r = self.s.post(
                'https://auth.riotgames.com/userinfo',
                headers={
                    'Authorization': f'Bearer {self.access_token}',
                    'User-Agent': self.user_agent
                },
                json={}
            )
            r.raise_for_status()
            self.sub_id = r.json()['sub']
        except Exception as e:
            print('Error fetching sub id:', e)
            exit()
    
    def get_daily_store(self):
        '''
        headers2 = {'Authorization': f'Bearer {token}', 'X-Riot-Entitlements-JWT': entitlement, 'Content-Type': 'text/plain'}
        
        json2 = [puuid]
        with session.get(f'https://pd.{region}.a.pvp.net/store/v2/storefront/{puuid}', headers=headers2, json=json2) as r:
            data = r.json()
        '''
        try:
            r = self.s.get(
                f'https://pd.{self.region}.a.pvp.net/store/v2/storefront/{self.sub_id}',
                headers={
                    'Authorization': f'Bearer {self.access_token}',
                    'X-Riot-Entitlements-JWT': self.entitlements_token,
                    'Content-Type': 'text/plain'
                },
                json=[self.sub_id]
            )
            r.raise_for_status()
            daily_stores = r.json()
        except Exception as e:
            print('Error fetching daily store:', e)
            exit()

        '''
        Parsing the daily store
        '''
        skinlevels = self.s.get('https://valorant-api.com/v1/weapons/skinlevels')
        skinlevels = skinlevels.json()['data']
        skinlevels = {skinlevel['uuid']: skinlevel['displayName'] for skinlevel in skinlevels}

        daily_store = []
        for item in daily_stores['SkinsPanelLayout']['SingleItemStoreOffers']:
            rewards = []
            for reward in item['Rewards']:
                skin = reward['ItemID']
                skin = skinlevels[skin]
                rewards.append(skin)
            daily_store.append('Name: {} | Cost: {} VP'.format(
                ', '.join(rewards),
                ', '.join(map(str, item['Cost'].values()))
            ))

        print('-'*20)
        print('DAILY STORE')
        print('-'*20)
        print(*daily_store, sep='\n')

if __name__=="__main__":
    parser = argparse.ArgumentParser(description='Valorant Account Checker')
    parser.add_argument('-u', '--username', help='Username', required=True)
    parser.add_argument('-p', '--password', help='Password', required=True)
    parser.add_argument('-r', '--region', help='Region', required=False, default='ap')
    args = parser.parse_args()
    
    client = ValorantClient(args.username, args.password, args.region)
    client.login()
    client.get_entitlements_token()
    client.get_sub_id()
    client.get_daily_store()