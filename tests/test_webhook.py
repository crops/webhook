# Copyright (C) 2016 Intel Corporation
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

import pytest
import os
from crops_webhook import WebhookApp
from configparser import RawConfigParser
from flask import Flask
import unittest.mock


@pytest.fixture
def app_config_file(request, tmpdir, handler_file, key_file):
    name = os.path.join(str(tmpdir), 'app_config')

    with open(name, 'w') as f:
        f.write("HANDLERS_FILE = '{}'\n".format(handler_file))
        f.write("KEY_FILE = '{}'\n".format(key_file))

    def fin():
        os.environ.pop('CROPS_WEBHOOK_CONFIG')

    request.addfinalizer(fin)
    os.environ['CROPS_WEBHOOK_CONFIG'] = name


@pytest.fixture
def flaskapp_mock():
    import flask
    mockflask = unittest.mock.create_autospec(Flask, specset=True)

    # config evidently can't be introspected out, so set it manually
    mockflask.config = unittest.mock.create_autospec(flask.Config,
                                                     specset=True)

    return mockflask


@pytest.fixture
def handler_file(tmpdir):
    name = os.path.join(str(tmpdir), 'handler_file')
    config = RawConfigParser()
    config['Handlers'] = {}
    config['Handlers']['testevent'] = 'foo'

    with open(name, 'w') as f:
        config.write(f)

    return name


@pytest.fixture
def key_file(tmpdir):
    name = os.path.join(str(tmpdir), 'key_file')

    with open(name, 'w') as f:
        f.write('foo')

    return name


def add_handler(filename, event, handler):
    config = RawConfigParser()
    config.read(filename)
    config['Handlers'][event] = handler

    with open(filename, 'w') as f:
        config.write(f)


# Actually use openssl to generate the digest so that we're not generating
# the digest using the same code we're trying to test
def get_digest(token, data):
    import subprocess
    # openssl evidently likes to change it's non binary output format, so
    # to try and "future proof" use binary
    cmd = "bash -c 'echo -n {} | openssl sha1 -binary -hmac {} | xxd -p'"
    cmd = cmd.format(data, token)

    return subprocess.check_output(cmd, shell=True).strip()


def test_arguments(flaskapp_mock):
    # Ensure the arguments are what is expected
    with pytest.raises(TypeError) as excinfo:
        WebhookApp()
    assert(("__init__() missing 1 required positional argument: "
            "'app'") in str(excinfo.value))

    # Ensure non flask arguments fail
    with pytest.raises(AssertionError):
        WebhookApp(0)


def test_verify_digest():
    token = "foo"
    data = "somedata"
    digest = b"sha1=" + get_digest(token, data)

    # Verify that a computed token by openssl matches one computed by
    # _verify_digest
    result = WebhookApp._verify_digest(token, data, digest)
    assert(result)

    # Verify that an invalid digest fails
    result = WebhookApp._verify_digest(token, data, "foo")
    assert(not result)


@pytest.fixture
def test_client(handler_file, app_config_file):
    app = Flask("mytestname")
    webhook = WebhookApp(app)
    return webhook.app.test_client()


@pytest.fixture
def headers():
    headers = {
                'X-Hub-Signature': 'foo',
                'X-GitHub-Event': 'foo',
              }
    return headers


class TestPost:
    def test_no_headers(self, test_client):
        # No headers
        rv = test_client.post('/webhook')

        print(rv.status_code)
        print(rv.data)

        assert(rv.status_code == 400)
        assert(b'No X-Hub-Signature header received' in rv.data)

    def test_invalid_auth(self, test_client, headers):
        # incorrect auth header
        headers['X-Hub-Signature'] = '0'
        rv = test_client.post('/webhook', headers=headers)

        print(rv.status_code)
        print(rv.data)

        assert(rv.status_code == 400)
        assert(b'Invalid value for X-Hub-Signature' in rv.data)

    def test_no_event(self, headers, test_client):
        # No event header
        token = "foo"
        data = "foo"
        headers.pop('X-GitHub-Event')
        headers['X-Hub-Signature'] = b'sha1=' + get_digest(token, data)
        rv = test_client.post('/webhook', headers=headers, data=data)

        print(rv.status_code)
        print(rv.data)

        assert(rv.status_code == 400)
        assert(b'No X-GitHub-Event header received' in rv.data)

    def test_valid_request(self, headers, test_client, handler_file):
        # Add always succesful handler
        handler = os.path.abspath("tests/handler_success_no_response.sh")
        add_handler(handler_file, "testevent", handler)

        token = "foo"
        data = 'fizz'

        # valid request
        headers['X-Hub-Signature'] = b'sha1=' + get_digest(token, data)
        headers['X-GitHub-Event'] = b'testevent'
        rv = test_client.post('/webhook', headers=headers, data=data)

        print(rv.status_code)
        print(rv.data)

        assert(rv.status_code == 200)
        assert(b'OK' in rv.data)


# Test payload file gets created with correct contents
def test_payload(test_client, handler_file, headers):
    # Add handler for checking the payload file is correct
    handler = os.path.abspath("tests/handler_test_payload.sh")
    add_handler(handler_file, "testevent", handler)

    token = "foo"
    data = 'expectedpayload'
    headers['X-Hub-Signature'] = b'sha1=' + get_digest(token, data)
    headers['X-GitHub-Event'] = b'testevent'

    # This should return 200
    rv = test_client.post('/webhook',
                          headers=headers,
                          data=data)
    print(rv.status_code)
    print(rv.data)
    assert(rv.status_code == 200)


# Test a handler that fails
def test_failed_handler(test_client, handler_file, headers):
    # Add handler for checking the payload file is correct
    handler = os.path.abspath("tests/handler_fail.sh")
    add_handler(handler_file, "testevent", handler)

    token = "foo"
    data = ''
    headers['X-Hub-Signature'] = b'sha1=' + get_digest(token, data)
    headers['X-GitHub-Event'] = b'testevent'

    # This should return 500
    rv = test_client.post('/webhook',
                          headers=headers,
                          data=data)
    print(rv.status_code)
    print(rv.data)

    assert(rv.status_code == 500)
    assert(rv.data == b'This thing failed')


# Test a successful handler
def test_successful_handler(test_client, handler_file, headers):
    # Add handler for checking the payload file is correct
    handler = os.path.abspath("tests/handler_success.sh")
    add_handler(handler_file, "testevent", handler)

    token = "foo"
    data = ''
    headers['X-Hub-Signature'] = b'sha1=' + get_digest(token, data)
    headers['X-GitHub-Event'] = b'testevent'

    # This should return 200
    rv = test_client.post('/webhook',
                          headers=headers,
                          data=data)
    print(rv.status_code)
    print(rv.data)

    assert(rv.status_code == 200)
    assert(rv.data == b'This thing worked')


# Test non-existent handler
def test_non_existent_handler(test_client, handler_file, headers):
    # Add handler for checking the payload file is correct
    handler = os.path.abspath("tests/notreallyahandler")
    add_handler(handler_file, "testevent", handler)

    token = "foo"
    data = ''
    headers['X-Hub-Signature'] = b'sha1=' + get_digest(token, data)
    headers['X-GitHub-Event'] = b'testevent'

    # This should return 200
    rv = test_client.post('/webhook',
                          headers=headers,
                          data=data)
    print(rv.status_code)
    print(rv.data)

    assert(rv.status_code == 500)
    assert(rv.data == b'Handler failure')
