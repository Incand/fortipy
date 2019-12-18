import pytest
from pytest_mock import mocker

import json
import requests

from fortipy.fortimanager import FortiManager


import logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


@pytest.fixture
def adom():
    return "Test_adom"


class MockResponse:
    def __init__(self, json_data, status_code):
        self.req = json.loads(json_data)
        self.text = json.dumps({
            'method': self.req['method'],
            'id': self.req['id'],
            'result': [{'data': {}, 'status': {'code': 0, 'message': 'OK'}}],
            'session': 'test_token'
        })
        self.status_code = status_code

    @property
    def ok(self):
        return True

    def json(self):
        return json.loads(self.text)


def mock_post(url, data, verify=False):
    print(url, data, verify)
    return MockResponse(data, 200)


def default_request_data(method, id_, params, session="test_token", verify=True):
    json_data = json.dumps({
        "method": method,
        "params": params,
        "id": id_, "verbose": False, "jsonrpc": "2.0", "session": session
    })
    return ('https://test.com:443/jsonrpc', json_data), {"verify": verify}


@pytest.fixture
def forti_manager(mocker):
    mocker.patch('requests.post', side_effect=mock_post)
    fm = FortiManager('test.com', 443, 'test_user', 'test_password')
    args, kwargs = default_request_data(
        "exec", 11, [{
            "url": "sys/login/user",
            "data": {"passwd": "test_password", "user": "test_user"}
        }], session=1
    )
    requests.post.assert_any_call(*args, **kwargs)
    return fm


def test_get_webfilter_ftgd_local_cats(forti_manager, adom):
    filter_ = ['desc', 'in', 'a', 'b', 'c']
    forti_manager.get_webfilter_ftgd_local_cats(adom, filter_=filter_)
    args, kwargs = default_request_data(
        "get", 8181, [{
            "url": "/pm/config/adom/Test_adom/obj/webfilter/ftgd-local-cat",
            "filter": filter_
        }]
    )
    requests.post.assert_any_call(*args, **kwargs)


def test_get_webfilter_ftgd_local_ratings(forti_manager, adom):
    filter_ = [["rating", "contain", 100], "||", ["rating", "contain", 101]]
    forti_manager.get_webfilter_ftgd_local_ratings(adom, filter_=filter_)
    args, kwargs = default_request_data(
        "get", 8183, [{
            "url": "/pm/config/adom/Test_adom/obj/webfilter/ftgd-local-rating",
            "filter": filter_
        }]
    )
    requests.post.assert_any_call(*args, **kwargs)


def test_add_webfilter_ftgd_local_ratings(forti_manager, adom):
    obj_data = [
        {"url": "test1.com", "status": "enable", "rating": [100]},
        {"url": "test2.com", "status": "enable", "rating": [101]},
        {"url": "test3.com", "status": "enable", "rating": [102]},
    ]
    forti_manager.add_webfilter_ftgd_local_ratings(adom, obj_data)
    args, kwargs = default_request_data(
        "add", 8184, [{
            "url": "/pm/config/adom/Test_adom/obj/webfilter/ftgd-local-rating",
            "data": obj_data
        }]
    )
    requests.post.assert_any_call(*args, **kwargs)


def test_update_webfilter_ftgd_local_ratings(forti_manager, adom):
    obj_data = [
        {"url": "test1.com", "status": "enable", "rating": [100]},
        {"url": "test2.com", "status": "enable", "rating": [101]},
        {"url": "test3.com", "status": "enable", "rating": [102]},
    ]
    forti_manager.update_webfilter_ftgd_local_ratings(adom, obj_data)
    args, kwargs = default_request_data(
        "update", 8185, [{
            "url": "/pm/config/adom/Test_adom/obj/webfilter/ftgd-local-rating",
            "data": obj_data
        }]
    )
    requests.post.assert_any_call(*args, **kwargs)


def test_delete_webfilter_ftgd_local_ratings(forti_manager, adom):
    obj_keys = ['a', 'b', 'c']
    forti_manager.delete_webfilter_ftgd_local_ratings(adom, obj_keys)
    args, kwargs = default_request_data(
        "delete", 8186, [{
            "url": "/pm/config/adom/Test_adom/obj/webfilter/ftgd-local-rating/",
            "filter": ["url", "in", "a", "b", "c"]
        }]
    )
    requests.post.assert_any_call(*args, **kwargs)
