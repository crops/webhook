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
import shutil
from crops_webhook import WebhookApp
from configparser import RawConfigParser
from flask import Flask
from unittest.mock import patch, Mock
import unittest.mock


@pytest.fixture
def app_config_file(request, tmpdir, handler_file, key_file, whitelist_file):
    name = os.path.join(str(tmpdir), 'app_config')

    with open(name, 'w') as f:
        f.write("HANDLERS_FILE = '{}'\n".format(handler_file))
        f.write("KEY_FILE = '{}'\n".format(key_file))
        f.write("WHITELIST_ENV = '{}'\n".format(whitelist_file))

    def fin():
        os.environ.pop('CROPS_WEBHOOK_CONFIG')

    request.addfinalizer(fin)
    os.environ['CROPS_WEBHOOK_CONFIG'] = name

    return name


@pytest.fixture
def whitelist_file(tmpdir):
    name = os.path.join(str(tmpdir), 'whitelist_file')

    config = RawConfigParser()
    config['Whitelist'] = {}
    config['Whitelist']['testevent'] = 'PATH'

    with open(name, 'w') as f:
        config.write(f)

    return name


def add_whitelist(filename, event, whitelist):
    config = RawConfigParser()
    config.read(filename)
    config['Whitelist'][event] = whitelist

    with open(filename, 'w') as f:
        config.write(f)


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


# Test a successful handler with a relative path
def test_successful_handler_relative(test_client, handler_file, headers):
    # Add handler for checking the payload file is correct
    dirname = os.path.dirname(handler_file)
    dirname = os.path.join(dirname, 'relativedir')

    os.mkdir(dirname)
    shutil.copy('tests/handler_success.sh', dirname)

    handler = 'relativedir/handler_success.sh'
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
    assert(b'Handler failure' in rv.data)


# Check that a key set in the environment is honored
def test_key_set_in_environment(request, flaskapp_mock):
    def fin():
        os.environ.pop('CROPS_WEBHOOK_KEY')
    request.addfinalizer(fin)

    os.environ['CROPS_WEBHOOK_KEY'] = 'testkey'
    webhook = WebhookApp(flaskapp_mock)

    assert(webhook.key == 'testkey')


# Verify that the correct handler is returned using both absolute or relative
# paths
def test_gethandler_expected_result(flaskapp_mock, handler_file):
    with patch('crops_webhook.get_key') as mock_get_key:
        webhook = WebhookApp(flaskapp_mock)

        # Common mocking
        flaskapp_mock.config = {}
        config = Mock()
        webhook._load_handlers_config = Mock(return_value=config)
        webhook._handler_sane = Mock(return_value=True)
        webhook.app.config['HANDLERS_FILE'] = handler_file
        dirname = os.path.dirname(handler_file)

        # Check absolute paths work as expected
        config.get = Mock(return_value='/absolute')
        handler = webhook._gethandler('')
        assert(handler == '/absolute')

        # Check relative paths work as expected
        config.get = Mock(return_value='relative')
        handler = webhook._gethandler('')
        assert(handler == os.path.join(dirname, 'relative'))


def test_get_env_from_whitelist(flaskapp_mock):
    webhook = WebhookApp(flaskapp_mock, loadconfig=False)

    ###############################
    # Test that no whitelist_config returns the current environment
    webhook.whitelist_config = None

    env = webhook._get_env_from_whitelist('testevent')
    assert(env == os.environ)
    ###############################

    ###############################
    # Test that an event that doesn't exist returns an empty environment
    whitelist_config = Mock()
    whitelist_config.get = Mock(return_value='')
    webhook.whitelist_config = whitelist_config

    # patch os.environ so it actually contains the values we are whitelisting
    env = webhook._get_env_from_whitelist('testevent')
    assert(env == {})
    ###############################

    ###############################
    # Test that the returned environment only contains the whitelisted values
    whitelist_env = {
                        'FIRSTENV': 'foo',
                        'SECONDENV': 'bar'
                    }
    whitelist_config = Mock()
    whitelist_config.get = Mock(return_value=' '.join(whitelist_env.keys()))
    webhook.whitelist_config = whitelist_config

    # patch os.environ so it actually contains the values we are whitelisting
    with patch.dict(os.environ, whitelist_env):
        env = webhook._get_env_from_whitelist('testevent')
        assert(env == whitelist_env)
    ###############################


def test_env_whitelist_in_handler(app_config_file, handler_file,
                                  whitelist_file, headers):
    app = Flask("mytestname")
    webhook = WebhookApp(app, loadconfig=False)

    # Add handler for checking the environment is correct
    handler = os.path.abspath("tests/handler_test_env.py")
    add_handler(handler_file, "testevent", handler)

    # Add whitelist
    whitelist_env = {
                        'FIRSTENV': 'foo',
                        'SECONDENV': 'bar'
                    }
    whitelist = ' '.join(list(whitelist_env))
    add_whitelist(whitelist_file, "testevent", whitelist)

    webhook.loadconfig()
    test_client = webhook.app.test_client()

    token = 'foo'
    data = ''
    headers['X-Hub-Signature'] = b'sha1=' + get_digest(token, data)
    headers['X-GitHub-Event'] = b'testevent'

    # patch os.environ so it actually contains the values we are whitelisting
    with patch.dict(os.environ, whitelist_env):
        # This should return 200
        rv = test_client.post('/webhook',
                              headers=headers,
                              data=data)
    print(rv.status_code)
    print(rv.data)

    assert(rv.status_code == 200)
