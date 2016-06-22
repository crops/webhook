#!/usr/bin/env python
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

# This checks that the environment only contains what is specified in
# test_env_whitelist_in_handler
import os
import sys

expected_env_vars = ['FIRSTENV', 'SECONDENV']

if set(os.environ.keys()) != set(expected_env_vars):
    responsefile = os.path.join(sys.argv[1], 'response')

    # Try to give some debug info in the response if the environment doesn't
    # match
    with open(responsefile, 'w') as f:
        f.write('env in handler:\n')
        for var in os.environ:
            f.write('{} = {}\n'.format(var, os.environ[var]))
        sys.exit(1)
