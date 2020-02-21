import sys
sys.path.append("./")
from app import app

import getpass
import json

import requests
from requests.auth import HTTPBasicAuth



def get_auth_admin_token():
    username = "admin@admin.pl"
    password = "12345"
    response = requests.get(
        'http://127.0.0.1:5000/login',
        auth=HTTPBasicAuth(username, password)
    )
    data = response.json()
    return data.get('token')

def test_get_all_users():
    auth_admin_token = get_auth_admin_token()
    response = requests.get(
        'http://127.0.0.1:5000/user',
        headers={'x-access-token': auth_admin_token}
    )
    assert response.status_code == 200

def test_status_code_get_one_user():
    auth_admin_token = get_auth_admin_token()
    response = requests.get(
        'http://127.0.0.1:5000/user/ef907b49-df31-44b4-b07d-7fab86af461b',
        headers={'x-access-token': auth_admin_token}
    )
    assert response.status_code == 200

def test_data_get_email_get_one_user():
    auth_admin_token = get_auth_admin_token()
    response = requests.get(
        'http://127.0.0.1:5000/user/ef907b49-df31-44b4-b07d-7fab86af461b',
        headers={'x-access-token': auth_admin_token}
    )
    data = response.json()
    assert data.get('user')['email'] == 'ala@wp.pl'

def test_create_user():
    auth_admin_token = get_auth_admin_token()
    response = requests.post(
        'http://127.0.0.1:5000/user',
        headers={'x-access-token': auth_admin_token},
        json={'email': 'zocha5@dupa.pl', 'password': '1234567'}
    )
    assert response.status_code == 200

def test_promote_user():
    auth_admin_token = get_auth_admin_token()
    response = requests.put(
        'http://127.0.0.1:5000/user/4aea0fbd-cbad-40bb-8031-30a81640b05d',
        headers={'x-access-token': auth_admin_token},
        data = {'admin': 'True'}
    )
    assert response.status_code == 200
"""
def test_delete_user():
    auth_admin_token = get_auth_admin_token()
    response = requests.get(
        'http://127.0.0.1:5000/user/xxxxxxxxxxxxxxxxxxxxxxxxxxx',
        headers={'x-access-token': auth_admin_token}
    )
    assert response.status_code == 000
"""