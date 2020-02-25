#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
@Author: reber
@Mail: reber0ask@qq.com
@Date: 2019-11-14 12:19:21
@LastEditTime : 2020-02-25 15:45:12
'''

from urllib.parse import quote
import urllib3
import requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from config import timeout
from libs.util import get_headers


class NoQuoteSession(requests.Session):
    """
    重写 requsts 的 send 方法，使不进行 urlencode
    重写 requsts 的 request 方法，设置默认超时时间、设置 verify 默认为 False
    """

    def send(self, prep, **send_kwargs):
        table = {
            quote('{'): '{',
            quote('}'): '}',
            quote(':'): ':',
            quote(','): ',',
        }
        for old, new in table.items():
            prep.url = prep.url.replace(old, new)
        return super(NoQuoteSession, self).send(prep, **send_kwargs)

    def request(self, method, url,
                params=None, data=None, headers=get_headers(), cookies=None, files=None,
                auth=None, timeout=timeout, allow_redirects=True, proxies=None,
                hooks=None, stream=None, verify=False, cert=None, json=None):

        # Create the Request.
        req = requests.Request(
            method=method.upper(),
            url=url,
            headers=headers,
            files=files,
            data=data or {},
            json=json,
            params=params or {},
            auth=auth,
            cookies=cookies,
            hooks=hooks,
        )
        prep = self.prepare_request(req)

        proxies = proxies or {}

        settings = self.merge_environment_settings(
            prep.url, proxies, stream, verify, cert
        )

        # Send the request.
        send_kwargs = {
            'timeout': timeout,
            'allow_redirects': allow_redirects,
        }
        send_kwargs.update(settings)
        resp = self.send(prep, **send_kwargs)

        return resp


req = NoQuoteSession()


if __name__ == "__main__":
    proxies = {"http": "http://127.0.0.1:8080",
               "https": "http://127.0.0.1:8080"}
    resp = req.get(url="https://google.com",
                   proxies=proxies, verify=False, timeout=10)
    print(resp.status_code)
