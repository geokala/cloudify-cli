########
# Copyright (c) 2014 GigaSpaces Technologies Ltd. All rights reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
#    * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    * See the License for the specific language governing permissions and
#    * limitations under the License.

"""
Tests 'cfy use'
"""

from mock import MagicMock
from mock import patch

from cloudify_rest_client import CloudifyClient
from cloudify_cli import utils

from cloudify_cli.tests import cli_runner
from cloudify_cli.tests.commands.test_cli_command import CliCommandTest


class UseTest(CliCommandTest):

    def test_use_command(self):
        self.client.manager.get_status = MagicMock()
        self.client.manager.get_context = MagicMock(
            return_value={
                'name': 'name',
                'context': {}}
        )
        self._create_cosmo_wd_settings()
        cli_runner.run_cli('cfy use -t 127.0.0.1')
        cwds = self._read_cosmo_wd_settings()
        self.assertEquals("127.0.0.1",
                          cwds.get_management_server())

    def test_use_command_no_prior_init(self):
        self.client.manager.get_status = MagicMock()
        self.client.manager.get_context = MagicMock(
            return_value={
                'name': 'name', 'context': {}
            }
        )
        cli_runner.run_cli('cfy use -t 127.0.0.1')
        cwds = self._read_cosmo_wd_settings()
        self.assertEquals('127.0.0.1', cwds.get_management_server())

    def test_secured_use(self):
        host = '127.0.0.1'
        auth_header = utils.create_auth_header(username='test_username',
                                               password='test_password')
        self.client = CloudifyClient(host=host, headers=auth_header)
        self.client.manager.get_context = MagicMock(
            return_value={
                'name': 'name',
                'context': {}
            }
        )

        self.headers = None

        def mock_do_request(*_, **kwargs):
            self.do_request_headers = kwargs.get('headers')
            return 'success'

        # run cli use command
        with patch('cloudify_rest_client.client.HTTPClient._do_request',
                   new=mock_do_request):
            cli_runner.run_cli('cfy use -t {0}'.format(host))

        # assert Authorization in headers
        eventual_request_headers = self.client._client.headers
        self.assertEqual(self.do_request_headers, eventual_request_headers)
