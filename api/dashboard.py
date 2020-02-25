#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
@Author: reber
@Mail: reber0ask@qq.com
@Date: 2019-08-17 09:45:15
@LastEditTime : 2020-02-25 15:03:52
'''

from config import TIMEOUT
from pprint import pprint
import requests
requests.packages.urllib3.disable_warnings()

class AwvsDashboard(object):
    """docstring for AwvsDashboard"""
    def __init__(self, api_url, api_key):
        super(AwvsDashboard, self).__init__()
        self.api = api_url
        self.headers = {
            "X-Auth": api_key,
            "Content-type": "application/json; charset=utf8"
        }

    def info(self):
        resp = requests.get(self.api+"/info", headers=self.headers, timeout=TIMEOUT, verify=False)
        return resp.json()
    
    def account(self):
        resp = requests.get(self.api+"/me", headers=self.headers, timeout=TIMEOUT, verify=False)
        return resp.json()
    
    def stats(self):
        resp = requests.get(self.api+"/me/stats", headers=self.headers, timeout=TIMEOUT, verify=False)
        return resp.json()

if __name__ == "__main__":
    from setting import API_URL
    from setting import API_KEY

    dashboard = AwvsDashboard(API_URL, API_KEY)
    pprint(dashboard.stats())