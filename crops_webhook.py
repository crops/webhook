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
from werkzeug.exceptions import BadRequest


class Config(object):
    HANDLERS_FILE = '/etc/crops-webhook/handlers.cfg'


class WebhookApp():
    def __init__(self, route, app):
        assert(type(route) == str)
        assert(isinstance(app, Flask))

        self.app = app

        # Load the application configuration
        self.app.config.from_object(Config)
        self.app.config.from_envvar('CROPS_WEBHOOK_CONFIG', silent=True)

        self.token = os.environ.get('WEBHOOK_SECRET_TOKEN', False)
        if not self.token:
            raise Exception("Unable to read WEBHOOK_SECRET_TOKEN")

        self.app.add_url_rule(route, view_func=self._webhook, methods=['POST'])
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

    def _authenticate(self, request):
        digest = request.headers.get('X-CROPS-Auth', False)
        if not digest:
            raise BadRequest('No X-CROPS-Auth header received')

        if not self._verify_digest(self.token, request.data, digest):
            raise BadRequest('Invalid value for X-CROPS-Auth')

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

    def _gethandler(self, headers):
        event = headers.get('X-CROPS-Event', False)
        if not event:
            raise BadRequest('No X-CROPS-Event header received')

        config = self._load_handlers_config()
        handler = config.get('Handlers', event, fallback=False)
        if not handler:
            raise BadRequest('No Handler for event {}'.format(event))

        return handler

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
        handler = self._gethandler(request.headers)

        tmpdir = tempfile.mkdtemp(suffix="cowsaregood")
        try:
            # Go ahead and store the payload to pass to the handler
            payload_file = os.path.join(tmpdir, 'payload')
            payload = request.get_data()
            with open(payload_file, 'wb') as f:
                f.write(payload)

            # Call the handler from the config
            cmd = [handler, tmpdir]
            print(cmd)
            rc = subprocess.call([handler, tmpdir])
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
