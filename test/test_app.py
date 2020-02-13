import sys
sys.path.append("./")
from app import app

import requests
import getpass
import json
from requests.auth import HTTPBasicAuth

def test_token_headers_body_json():
    username= "admin@admin.pl"
    password= "12345"
    response = requests.get(
        'http://127.0.0.1:5000/login',
        auth=HTTPBasicAuth(username, password),  # basic authentication
        )

    data = response.json()  # get response as parsed json (will return a dict)
    auth_token = data.get('token')

    response = requests.get(
        'http://127.0.0.1:5000/user',
        headers={
            'x-access-token': auth_token
        })

    assert response.status_code == 200
