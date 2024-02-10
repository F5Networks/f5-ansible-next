# -*- coding: utf-8 -*-
#
# Copyright: (c) 2023, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os
from unittest.mock import Mock
from unittest import TestCase

from ansible.errors import AnsibleConnectionFailure
from ansible.module_utils.six.moves.urllib.error import HTTPError
from ansible.module_utils.six import StringIO
from ansible.playbook.play_context import PlayContext
from ansible.plugins.loader import connection_loader

from ansible_collections.f5networks.next.plugins.module_utils.common import F5ModuleError
from ansible_collections.f5networks.next.tests.utils.common import connection_response

fixture_path = os.path.join(os.path.dirname(__file__), 'fixtures')
fixture_data = {}


def load_fixture(name):
    path = os.path.join(fixture_path, name)

    if path in fixture_data:
        return fixture_data[path]

    with open(path) as f:
        data = f.read()

    try:
        data = json.loads(data)
    except Exception:
        pass

    fixture_data[path] = data
    return data


class TestNextHttpapi(TestCase):
    def setUp(self):
        self.pc = PlayContext()
        self.pc.network_os = "f5networks.next.cm"
        self.connection = connection_loader.get("ansible.netcommon.httpapi", self.pc, "/dev/null")
        self.mock_send = Mock()
        self.connection.send = self.mock_send
        self.connection.httpapi.set_option('debug_mode', True)
        self.connection.httpapi.set_option('debug_level', 'debug')

    def test_login_raises_exception_when_username_and_password_are_not_provided(self):
        with self.assertRaises(AnsibleConnectionFailure) as res:
            self.connection.httpapi.login(None, None)
        self.assertIn('Username and password are required for login.', res.exception.args[0])

    def test_login_raises_exception_when_invalid_token_response(self):
        self.connection.send.return_value = connection_response(
            {'token': {'BAZ': 'BAR'},
             'refreshToken': {'BAZ': 'BAR'}}
        )

        with self.assertRaises(AnsibleConnectionFailure) as res:
            self.connection.httpapi.login('foo', 'bar')

        self.assertIn('Server returned invalid response during connection authentication.', res.exception.args[0])

    def test_send_request_should_return_error_info_when_http_error_raises(self):
        self.connection.send.side_effect = HTTPError(
            'http://bigip.local', 400, '', {}, StringIO('{"errorMessage": "ERROR"}')
        )

        with self.assertRaises(AnsibleConnectionFailure) as res:
            self.connection.httpapi.login('foo', 'bar')

        self.assertIn("server returned: {'errorMessage': 'ERROR'}", res.exception.args[0])

    def test_login_success(self):
        self.connection.send.return_value = connection_response(load_fixture('cm_auth_response.json'))

        token = "Z1sRFOE5acR6saotGyOxfAwnX84g2B2bwEAYC0UYHXExVUtzBodFUKVD+pXS7cW4uPPX9u+BLvRusKxvk3dK8D41MichCPXh+0T" \
                "3W6b67OpqYIIr4qfKe6W6x4833UiAzJ8QbbrKLY0/cA4UGeWoPwovS0i4Xf3yW6h3Ue4s6MLIlKnhyiXh6FT+UITe4CXrQnwrTV" \
                "TAr30hI7BhhH4fkjKVrfF48tb63j8THMu0WUXPMcXegc8xNasTAX7Nw0/JOeYHfnv1HrqqlSz0B/n7xK7151NMlk2cfUOdkU3XX" \
                "zUrFUquAutIiuJ++2Q0+Sae84+r8YTmZfg0pQXRejIAO8I7EYQ4mDRVzbkQLQ+5vLKs+78TxDUH1ulf0L2mwy4fYDxKOIc/8IcF" \
                "1Tu+TX5gygisi/vkH3klIjxhE3TL2Cdlj13wP640yw7PA6rjtmwqkt0M9koL3WPKgJ/+UaAydTd07K/YCeOLdyQvfhnTVBXlkB3" \
                "MNZP24r3enhyBFydvy7cdwUh8les0Cv7078xYTTJ2JqunE0TymQuPHhfiwg=="
        refresh = "Z1sRFOE5acR6saotGyOxfAwnX84g2B2bwEAYC0UYHXExVUtzBodFUKVD+pXS7cW4uPPX9u+BLvRusKxvk3dK8D41MichCPXh+" \
                  "0T3W6b67OpqYIIr4qfKd+64+a033UiAzJ8QbbrKLY0/cA4UGeWoPwovS0i4Xf3yW6h3Ue4s6MLIlKnhyiXh6FT+UITe4CXrQn" \
                  "wrTVTAr30hI7BhhH4fkjKVrfF48tb63j8THMu0WUaVMbPogc8MJaoEAX/d1E/ZN+YHfnr1QaqqlRHjXvnrxfT19EgRgl2LJVW" \
                  "NtwXXTyErFUquAutIiuJ++2Q0+Sae84+r8YTmZfg0pQXRejIAO8I7EYQ4mDRVzbkQLQ+5vLKs+78TxDUH1ulf0L2mwy4fYDxK" \
                  "OIc/8IcF1Tu+TX5gygisi/vkH3klIksTN1WU4RVoo2KvD98vxxvtAZiItGEu5tQnpScGvGfIt7HCIcw9TD0isZjgP7iBeTIod" \
                  "zfkXCnunkbDUqHh54D2pQqsQS9b0ZAi5nReju45Gf/Y6epYZX1IX2WQwIZMH4v5Sn9CnA=="

        self.connection.httpapi.login('foo', 'bar')

        self.assertTrue(self.connection.httpapi.access_token == token)
        self.assertTrue(self.connection.httpapi.refresh_token == refresh)
        self.assertTrue(self.connection._auth == {'Authorization': 'Bearer' + ' ' + token})

    def test_token_refresh(self):
        token_1 = "Z1sRFOE5acR6saotGyOxfAwnX84g2B2bwEAYC0UYHXExVUtzBodFUKVD+pXS7cW4uPPX9u+BLvRusKxvk3dK8D41MichCPXh+0" \
                  "T3W6b67OpqYIIr4qfKe6S4x6E33liAzJ8QbbrKLY0/cA4UGeWoBU4uZUjwXf3yW6h3Ue4s6MLIlKnhyiXh6FT+UITe4CXrQnwr" \
                  "TVTAr0dlIp5hiX4fkjKVrfF48tb63j8THMu0WUXKMaPOzM4hNakHEX/d1EjdOeYHfW7hJ4yqgyzvFfrBxff19FAXgl6AfEGzuw" \
                  "fATzErFUquAutIiuJ++2Q0+Sae84+r8YTmZfg0pQXRejIAO8I7EYQ4mDRVzbkQLQ+5vLKs+78TxDUH1ulf0L2mwy4fYDxKOIc/" \
                  "8IcF1Tu+TX5gygisi/vkH3klIg0+LHaV7SF7nD6YSdcCzT7zGJWG8lcMz+UoqXwq1zTdus7hAqsdfgsxtovpDJqCIGIUfBDEB3" \
                  "fQxh7+QLDK+5/mqGC9cTNAwuM/qUxJq88LLtPf1fBIZMu3mxYW7D7z6LPrZdfucg=="
        token_2 = "UC/sxg3tca1FkCk64RRD54Y/8BpUC5JAyggRzw2mqT+t+3dLLnQM0Yhhb6TTuZ/m7kQ6UhBBDpw8lzqnAFw9eWSWCG/G1XJ94x" \
                  "yUhHQpqIXSBQzxNruU1ox/jENc30BA4XlJnKPvW+YE3mkW3S9+8EgvjkDLlH0hwJhT/fLSudWoBW08DZglio/fivw89KXpjLC8" \
                  "0nIS52RcHfWyqMPh+HvBgN6EYxqdJlqer0zM+6pcRf9Zp9Td4+4B5N2zJQk8wY6ERNfQMalhYvO0AY2mebukzo34V7S93pOlB+" \
                  "93CHga64pP+eKr4/0Ai9XR1VIbw/byQGjydUwukk2GTv+NRKc7JPMAsOxSLI6Rt/SXm7Adu1bMx9PVgI6r1xqgWIAZU/oA+qJU" \
                  "Ud3x1/YEpmoI4m9Htmi94cT3SxxndmIQAuE3/FqpUA6F4x32bw1gwiWHnMWvFVZu7ixUXkxkkGlE/uahnYCznrmjve7ZrnDwvt" \
                  "6qJIusQVV5lAXOBhtHR7ACevWxk/+Q9OWeeXcMkx7MXNYGe74Q8EdWDZLqoE2ukA=="
        refresh = "Z1sRFOE5acR6saotGyOxfAwnX84g2B2bwEAYC0UYHXExVUtzBodFUKVD+pXS7cW4uPPX9u+BLvRusKxvk3dK8D41MichCPXh+0" \
                  "T3W6b67OpqYIIr4qfKe6O76ZM33liAzJ8QbbrKLY0/cA4UGeWoBU4uZUjwXf3yW6h3Ue4s6MLIlKnhyiXh6FT+UITe4CXrQnwr" \
                  "TVTAr0dlIp5hiX4fkjKVrfF48tb63j8THMu0WUaSJZrRks4yG6gEK36H11/Je+YHfWn2GbaqlS/nFfvRxfb12n5SgnOlI0Kev0" \
                  "/VXBMrFUquAutIiuJ++2Q0+Sae84+r8YTmZfg0pQXRejIAO8I7EYQ4mDRVzbkQLQ+5vLKs+78TxDUH1ulf0L2mwy4fYDxKOIc/" \
                  "8IcF1Tu+TX5gygisi/vkH3klIi80H1DDnRRnmEKJE9MOzmC+W6nk5EwGye58vHIgomXShYnjMJ8rchUn6urkKrrWfSMVTHbcfy" \
                  "DGxGG5YMHn4LDeugW0bxhEzbQAznxXtMYTKvrO5OVIr54avNbDUTroz80XQ453DA=="

        self.connection.send.side_effect = [
            connection_response(load_fixture('cm_auth_response_2.json')),
            connection_response(load_fixture('cm_token_refresh.json'))
        ]

        self.connection.httpapi.login('baz', 'bar')

        self.assertTrue(self.connection.httpapi.access_token == token_1)
        self.assertTrue(self.connection.httpapi.refresh_token == refresh)
        self.assertTrue(self.connection._auth == {'Authorization': 'Bearer' + ' ' + token_1})

        self.connection.httpapi.token_refresh()
        self.assertTrue(self.connection.httpapi.access_token == token_2)
        self.assertTrue(self.connection.httpapi.refresh_token == refresh)
        self.assertTrue(self.connection._auth == {'Authorization': 'Bearer' + ' ' + token_2})

    def test_token_refresh_invalid_token_raises(self):
        self.connection.send.side_effect = [
            connection_response(load_fixture('cm_auth_response_2.json')),
            connection_response({'token': {'BAZ': 'BAR'}, 'refreshToken': {'BAZ': 'BAR'}})
        ]
        self.connection.httpapi.login('baz', 'bar')

        with self.assertRaises(AnsibleConnectionFailure) as exc:
            self.connection.httpapi.token_refresh()

        self.assertIn("Server returned invalid response during token refresh", exc.exception.args[0])

    def test_token_refresh_invalid_response_raises(self):
        self.connection.send.side_effect = [
            connection_response(load_fixture('cm_auth_response_2.json')),
            HTTPError(
                'http://bigip.local', 400, '', {}, StringIO('{"errorMessage": "ERROR"}')
            )
        ]
        self.connection.httpapi.login('baz', 'bar')

        with self.assertRaises(AnsibleConnectionFailure) as exc:
            self.connection.httpapi.token_refresh()

        self.assertIn("server returned: {'errorMessage': 'ERROR'}", exc.exception.args[0])

    def test_logout_succeeds(self):
        self.connection.send.side_effect = [
            connection_response(load_fixture('cm_auth_response.json')),
            connection_response({})
        ]
        token = "Z1sRFOE5acR6saotGyOxfAwnX84g2B2bwEAYC0UYHXExVUtzBodFUKVD+pXS7cW4uPPX9u+BLvRusKxvk3dK8D41MichCPXh+0T" \
                "3W6b67OpqYIIr4qfKe6W6x4833UiAzJ8QbbrKLY0/cA4UGeWoPwovS0i4Xf3yW6h3Ue4s6MLIlKnhyiXh6FT+UITe4CXrQnwrTV" \
                "TAr30hI7BhhH4fkjKVrfF48tb63j8THMu0WUXPMcXegc8xNasTAX7Nw0/JOeYHfnv1HrqqlSz0B/n7xK7151NMlk2cfUOdkU3XX" \
                "zUrFUquAutIiuJ++2Q0+Sae84+r8YTmZfg0pQXRejIAO8I7EYQ4mDRVzbkQLQ+5vLKs+78TxDUH1ulf0L2mwy4fYDxKOIc/8IcF" \
                "1Tu+TX5gygisi/vkH3klIjxhE3TL2Cdlj13wP640yw7PA6rjtmwqkt0M9koL3WPKgJ/+UaAydTd07K/YCeOLdyQvfhnTVBXlkB3" \
                "MNZP24r3enhyBFydvy7cdwUh8les0Cv7078xYTTJ2JqunE0TymQuPHhfiwg=="

        self.connection.httpapi.login('foo', 'bar')

        self.assertTrue(self.connection._auth == {'Authorization': 'Bearer' + ' ' + token})

        self.connection.httpapi.logout()
        self.assertTrue(self.connection.send.call_args[0][0] == '/api/logout')
        self.assertTrue(self.connection.send.call_args[0][1] == '{}')
        self.assertTrue(self.connection.send.call_args[1] == dict(
            method='POST', headers={'Content-Type': 'application/json'}
        ))

    def test_handle_http_error(self):
        exc1 = HTTPError('http://bigip.local', 403, '', {}, StringIO('{"errorMessage": "not allowed"}'))
        res1 = self.connection.httpapi.handle_httperror(exc1)

        self.assertFalse(res1)

        exc2 = HTTPError('http://bigip.local', 401, '', {}, StringIO('{"errorMessage": "unauthorized"}'))
        res2 = self.connection.httpapi.handle_httperror(exc2)

        self.assertFalse(res2)

        self.connection.send.side_effect = [
            connection_response(load_fixture('cm_auth_response.json')),
            connection_response(load_fixture('cm_token_refresh.json'))
        ]

        token = "Z1sRFOE5acR6saotGyOxfAwnX84g2B2bwEAYC0UYHXExVUtzBodFUKVD+pXS7cW4uPPX9u+BLvRusKxvk3dK8D41MichCPXh+0T" \
                "3W6b67OpqYIIr4qfKe6W6x4833UiAzJ8QbbrKLY0/cA4UGeWoPwovS0i4Xf3yW6h3Ue4s6MLIlKnhyiXh6FT+UITe4CXrQnwrTV" \
                "TAr30hI7BhhH4fkjKVrfF48tb63j8THMu0WUXPMcXegc8xNasTAX7Nw0/JOeYHfnv1HrqqlSz0B/n7xK7151NMlk2cfUOdkU3XX" \
                "zUrFUquAutIiuJ++2Q0+Sae84+r8YTmZfg0pQXRejIAO8I7EYQ4mDRVzbkQLQ+5vLKs+78TxDUH1ulf0L2mwy4fYDxKOIc/8IcF" \
                "1Tu+TX5gygisi/vkH3klIjxhE3TL2Cdlj13wP640yw7PA6rjtmwqkt0M9koL3WPKgJ/+UaAydTd07K/YCeOLdyQvfhnTVBXlkB3" \
                "MNZP24r3enhyBFydvy7cdwUh8les0Cv7078xYTTJ2JqunE0TymQuPHhfiwg=="

        token_2 = "UC/sxg3tca1FkCk64RRD54Y/8BpUC5JAyggRzw2mqT+t+3dLLnQM0Yhhb6TTuZ/m7kQ6UhBBDpw8lzqnAFw9eWSWCG/G1XJ94x" \
                  "yUhHQpqIXSBQzxNruU1ox/jENc30BA4XlJnKPvW+YE3mkW3S9+8EgvjkDLlH0hwJhT/fLSudWoBW08DZglio/fivw89KXpjLC8" \
                  "0nIS52RcHfWyqMPh+HvBgN6EYxqdJlqer0zM+6pcRf9Zp9Td4+4B5N2zJQk8wY6ERNfQMalhYvO0AY2mebukzo34V7S93pOlB+" \
                  "93CHga64pP+eKr4/0Ai9XR1VIbw/byQGjydUwukk2GTv+NRKc7JPMAsOxSLI6Rt/SXm7Adu1bMx9PVgI6r1xqgWIAZU/oA+qJU" \
                  "Ud3x1/YEpmoI4m9Htmi94cT3SxxndmIQAuE3/FqpUA6F4x32bw1gwiWHnMWvFVZu7ixUXkxkkGlE/uahnYCznrmjve7ZrnDwvt" \
                  "6qJIusQVV5lAXOBhtHR7ACevWxk/+Q9OWeeXcMkx7MXNYGe74Q8EdWDZLqoE2ukA=="

        self.connection.httpapi.login('baz', 'bar')
        self.assertTrue(self.connection._auth == {'Authorization': 'Bearer' + ' ' + token})

        exc3 = HTTPError('http://bigip.local', 401, '', {}, StringIO('{"errorMessage": "not allowed"}'))
        res3 = self.connection.httpapi.handle_httperror(exc3)

        self.assertTrue(res3)
        self.assertTrue(self.connection._auth == {'Authorization': 'Bearer' + ' ' + token_2})

    def test_resonse_to_json_raises(self):
        with self.assertRaises(F5ModuleError) as err:
            self.connection.httpapi._response_to_json('invalid json}')
        assert 'Invalid JSON response: invalid json}' in str(err.exception)

    def test_send_multipart(self):
        mock_uri = '/foo/bar/baz/a23dfdf454546dfgs'
        mock_form = {'content': {'filename': os.path.join(fixture_path, 'fake_file_upload.json')},
                     'file_name': 'test.txt'
                     }
        self.connection.send.side_effect = [
            connection_response(load_fixture('fake_file_upload.json')),
            HTTPError(
                'http://bigip.local', 400, '', {}, StringIO('{"errorMessage": "ERROR"}')
            )
        ]

        result = self.connection.httpapi.send_multipart(mock_uri, mock_form)
        expected = {'code': 200,
                    'contents': {'_links': {'self': {'href': '/v1/files/45320e51-2798-4262-8df9-c3c8925bc783'}},
                                 'filename': 'simple_test.pdf', 'id': '45320e51-2798-4262-8df9-c3c8925bc783',
                                 'message': 'File uploaded!'}, 'headers': {'Content-Type': 'application/json'}
                    }
        self.assertDictEqual(expected, result)

        error = self.connection.httpapi.send_multipart(mock_uri, mock_form)

        self.assertEqual(error['code'], 400)
        self.assertDictEqual(error['contents'], {'errorMessage': 'ERROR'})
