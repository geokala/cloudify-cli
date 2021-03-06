########
# Copyright (c) 2015 GigaSpaces Technologies Ltd. All rights reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
############

import os
import unittest

from cloudify_cli import utils
from cloudify_cli.constants import CLOUDIFY_USERNAME_ENV
from cloudify_cli.constants import CLOUDIFY_PASSWORD_ENV
from cloudify_cli.constants import CLOUDIFY_AUTHENTICATION_HEADER


class TestGetRestClient(unittest.TestCase):

    def setUp(self):
        os.environ[CLOUDIFY_USERNAME_ENV] = 'test_username'
        os.environ[CLOUDIFY_PASSWORD_ENV] = 'test_password'

    def tearDown(self):
        del os.environ[CLOUDIFY_USERNAME_ENV]
        del os.environ[CLOUDIFY_PASSWORD_ENV]

    def test_get_rest_client(self):
        client = utils.get_rest_client(
            manager_ip='localhost', rest_port=80)
        self.assertIsNotNone(
            client._client.headers[CLOUDIFY_AUTHENTICATION_HEADER])
