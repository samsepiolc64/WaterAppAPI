import sys
sys.path.append("./")
from app import app

import getpass
import json

import requests
from requests.auth import HTTPBasicAuth


def get_auth_token():
    username = "admin@admin.pl"
    password = "12345"
    response = requests.get(
        'http://127.0.0.1:5000/login',
        auth=HTTPBasicAuth(username, password)
    )
    data = response.json()
    return data.get('token')

def test_get_all_users():
    auth_token = get_auth_token()
    response = requests.get(
        'http://127.0.0.1:5000/user',
        headers={'x-access-token': auth_token}
    )
    assert response.status_code == 200