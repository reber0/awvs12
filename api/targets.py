#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
@Author: reber
@Mail: reber0ask@qq.com
@Date: 2019-08-17 10:41:19
@LastEditTime: 2019-08-18 03:41:43
'''

from config import TIMEOUT
from pprint import pprint
import json
import requests
requests.packages.urllib3.disable_warnings()

class AwvsTargets(object):
    """docstring for AwvsTargets"""
    def __init__(self, api_url, api_key):
        super(AwvsTargets, self).__init__()
        self.api = api_url
        self.headers = {
            "X-Auth": api_key,
            "Content-type": "application/json; charset=utf8"
        }

    def get_all_target_info(self):
        resp = requests.get(self.api+"/targets", headers=self.headers, timeout=TIMEOUT, verify=False)
        return resp.json()

    #不太好用，如果target没有开始扫描或者开始扫描但是没有漏洞信息，用这个接口是得不到信息的
    def get_single_target_info_api(self, text_search, threat="1,2,3", criticality="10,20,30"):
        '''
        threat        int     威胁等级;高->低:[3,2,1,0]
        criticality   int     危险程度;高->低:[30,20,10,0]
        group_id      string  分组id
        last_scanned          最后一次扫描时间(默认不传该参数)
        text_search   string  筛选内容

        Demo: /api/v1/targets?q=threat:3;criticality:10,20;text_search:*h4rdy.me
        '''

        path = "/targets?q=threat:{};criticality:{};text_search:*{}".format(
            threat, criticality, text_search
        )
        resp = requests.get(self.api+path, headers=self.headers, timeout=TIMEOUT, verify=False)
        return resp.json()

    def get_single_target_info(self, target):
        target_list = self.get_all_target_info()
        for _ in target_list.get("targets"):
            if target.rstrip("/") in _.get("address"):
                return _
        return None

    def get_target_id(self, target):
        target_list = self.get_all_target_info()
        for _ in target_list.get("targets"):
            if target.rstrip("/") in _.get("address"):
                return _.get("target_id")
        return None

    def add_target(self, target, criticality="10", description="awvs_scan"):
        '''
        address       string  目标网址:需 http 或 https 开头
        criticality   int     危险程度;范围:[30,20,10,0];默认为10
        description   string  备注
        '''

        data = json.dumps({
            "address": target.rstrip("/"),
            "description": description,
            "criticality": criticality,
        })
        resp = requests.post(self.api+"/targets", data=data, headers=self.headers, timeout=TIMEOUT, verify=False)
        return resp.json()

    def delete_target(self, target_id):
        path = "/targets/{}".format(target_id)
        resp = requests.delete(self.api+path, headers=self.headers, timeout=TIMEOUT, verify=False)
        return resp.json()
    
    def proxy(self, target_id, address="127.0.0.1", protocal="http", port=8080, username="", password=""):
        data = json.dumps({
            "proxy": {
                "enabled": True,
                "address": address,
                "protocol": protocal,
                "port": port,
                "username": username,
                "password": password,
            }
        })
        path = "/targets/{target_id}/configuration".format(target_id=target_id)
        requests.patch(self.api+path, data=data, headers=self.headers, timeout=TIMEOUT, verify=False)


if __name__ == "__main__":
    from setting import API_URL
    from setting import API_KEY

    targets = AwvsTargets(API_URL, API_KEY)
    # pprint(targets.get_all_target_info())
    # pprint(targets.add_target("http://xxx.com"))
    # target_id = targets.get_target_id("test.com")
    # print(target_id)
    pprint(targets.get_single_target_info("http://testphp.vulnweb.com"))
    # print(targets.delete_target(target_id))
    # targets.proxy(target_id)

