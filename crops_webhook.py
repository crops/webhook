# webhook.py
#
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

import os
import hmac
import hashlib
import werkzeug.security
import logging
import tempfile
import shutil
import subprocess
from configparser import RawConfigParser
from http.server import BaseHTTPRequestHandler, HTTPServer
from flask import Flask, request, send_file
from werkzeug.exceptions import BadRequest, InternalServerError


# Just returns the first non empty line from a file
def get_key(keyfile):
    key = ''
    with open(keyfile, 'r') as f:
        for line in f:
            key = line.strip()
            if len(key) != 0:
                break

    if not key:
        raise Exception('Unable to find a key in {}'.format(keyfile))
    else:
        return key


class Config(object):
    HANDLERS_FILE = '/etc/crops-webhook/handlers.cfg'
    KEY_FILE = '/etc/crops-webhook/key'
    ROUTE = '/webhook'
    WHITELIST_ENV = ''


class WebhookApp():
    def __init__(self, app, loadconfig=True):
        assert(isinstance(app, Flask))

        self.app = app
        self.key = None
        self.whitelist_config = None

        if loadconfig:
            self.loadconfig()

    def loadconfig(self):
        # Load the application configuration
        self.app.config.from_object(Config)
        self.app.config.from_envvar('CROPS_WEBHOOK_CONFIG', silent=True)

        # If the key is in the environment, it has a higher priority than
        # any other config.
        self.key = (os.getenv('CROPS_WEBHOOK_KEY', '') or
                    get_key(self.app.config['KEY_FILE']))

        # Since the environment can't be changed once the app is running, there
        # is no reason to try to do lazy loading of the environment whitelist.
        self.whitelist_config = self._get_whitelist_config()

        self.app.add_url_rule(self.app.config['ROUTE'],
                              view_func=self._webhook,
                              methods=['POST'])
        self.app.register_error_handler(BadRequest, self._errorhandler)

    @staticmethod
    def _errorhandler(error):
        return error

    # For now assume github style signatures which are assumes "sha1=" is
    # prepended to the signature
    @staticmethod
    def _verify_digest(token, payload, digest):
        # hmac always expects bytes so encode if necessary
        if type(token) != bytes:
            token = token.encode()
        if type(payload) != bytes:
            payload = payload.encode()
        if type(digest) != bytes:
            digest = digest.encode()

        computed_digest = "sha1=" + hmac.new(token,
                                             payload,
                                             hashlib.sha1).hexdigest()

        if type(computed_digest) != bytes:
            computed_digest = computed_digest.encode()

        return hmac.compare_digest(digest, computed_digest)

    def _get_whitelist_config(self):
        whitelist_file = self.app.config.get('WHITELIST_ENV')
        if whitelist_file:
            config = RawConfigParser()
            config.read(whitelist_file)

            return config
        else:
            return None

    def _authenticate(self, request):
        digest = request.headers.get('X-Hub-Signature', False)
        print(request.headers)
        if not digest:
            raise BadRequest('No X-Hub-Signature header received')

        if not self._verify_digest(self.key, request.get_data(), digest):
            raise BadRequest('Invalid value for X-Hub-Signature')

    def _load_handlers_config(self):
        handlers_file = self.app.config['HANDLERS_FILE']
        if not os.path.exists(handlers_file):
            raise Exception("{} file does not exist".format(handlers_file))
        else:
            config = RawConfigParser()
            config.read(handlers_file)
            if not config.has_section('Handlers'):
                raise Exception("{} does not have a 'Handlers' section")

        return config

    def _gethandler(self, event):
        config = self._load_handlers_config()
        handler = config.get('Handlers', event, fallback=False)
        if not handler:
            raise BadRequest('No Handler for event {}'.format(event))

        # We are now assuming all non-absolute path handlers are relative to
        # the handlers.cfg. This assumption allows us to actually get to the
        # handlers without mucking with the path or iterating over some set of
        # "handler directories"
        if not handler.startswith('/'):
            handlers_file = self.app.config['HANDLERS_FILE']
            dirname = os.path.dirname(handlers_file)
            handler = os.path.join(dirname, handler)

        if not self._handler_sane(handler):
            raise InternalServerError('Handler failure')

        return handler

    # Basic sanity checks on the handler such that it is executable,
    # exists, etc.
    def _handler_sane(self, handler):
        return os.access(handler, os.F_OK | os.R_OK | os.X_OK)

    def _get_env_from_whitelist(self, event):
        config = self.whitelist_config

        # If there is no config, don't restrict the environment.
        if not config:
            return os.environ.copy()

        # If the config exists but there is no match for the event, use an
        # empty environment.
        envwhitelist = config.get('Whitelist', event, fallback='').split()
        if not envwhitelist:
            return {}

        # Now since the event was found in the config, return an environment
        # only containing variables on the whitelist
        env = {}
        for var in envwhitelist:
            if var in os.environ:
                env[var] = os.environ[var]

        return env

    # The hook will run and it will create a temporary directory with the
    # file: "payload".
    # payload is the payload written to the file.
    # The temporary directory is then passed as the argument to the handler.
    #
    # When the handler finishes, it can create a file "response". If the
    # handler exits successfully or fails, if there is a response file it will
    # be sent as the response payload.
    def _webhook(self):
        self._authenticate(request)

        event = request.headers.get('X-GitHub-Event', False)
        if not event:
            raise BadRequest('No X-GitHub-Event header received')

        handler = self._gethandler(event)

        tmpdir = tempfile.mkdtemp(suffix="cowsaregood")
        try:
            # Go ahead and store the payload to pass to the handler
            payload_file = os.path.join(tmpdir, 'payload')
            payload = request.get_data()
            with open(payload_file, 'wb') as f:
                f.write(payload)

            # Get the environment to use for the event/handler
            whitelist_env = self._get_env_from_whitelist(event)

            # Call the handler from the config
            cmd = [handler, tmpdir]
            print(cmd)
            rc = subprocess.call([handler, tmpdir], env=whitelist_env)
            if rc != 0:
                status_code = 500
            else:
                status_code = 200

            response_file = os.path.join(tmpdir, 'response')

            if os.path.exists(response_file):
                return send_file(response_file), status_code
            else:
                response = ''
                if status_code == 200:
                    response = 'OK'
                return response, status_code
        finally:
            shutil.rmtree(tmpdir)
