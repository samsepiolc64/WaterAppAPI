from flask import Flask
import json
import unittest
from waterapp import app
import pytest

@pytest.fixture

def client(request):
    test_client = app.test_client()
    def teardown():
        pass
    request.addfinalizer(teardown)
    return test_client

def post_json(client, url, json_dict):
    return client.post(url, data = json.dumps(json_dict), content_type='application/json')

def json_of_response(response):
    return json.loads(response.data.decode('utf8'))

def test_json(client):
    response = post_json(client, '/add', {'key': 'value'})
    assert response.status_code == 200
    assert json_of_response(response) == {"answer": 'value' * 2}
