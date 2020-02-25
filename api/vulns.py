#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
@Author: reber
@Mail: reber0ask@qq.com
@Date: 2019-08-17 18:07:06
@LastEditTime : 2020-02-25 15:47:13
'''

import json

from libs.request import req as requests


class AwvsVulns(object):
    """docstring for AwvsVulns"""
    def __init__(self, api_url, api_key):
        super(AwvsVulns, self).__init__()
        self.api = api_url
        self.headers = {
            "X-Auth": api_key,
            "Content-type": "application/json; charset=utf8"
        }

    def get_single_vuln(self, vuln_id):
        path = "/vulnerabilities/{}".format(vuln_id)
        resp = requests.get(self.api+path, headers=self.headers)
        result = resp.json()

        script = result.get("source") #使用的脚本
        vt_name = result.get("vt_name")
        vul_level = result.get("severity")
        affects_url = result.get("affects_url")
        affects_detail = result.get("affects_detail")
        request = result.get("request")

        return vt_name, vul_level, affects_url, affects_detail, request

    #按状态和等级获取某个target的漏洞
    def get_target_vulns_by_status_severity(self, target_id, status, severity):
        '''
        target_id   string  target_id
        status      string  状态;[open !open fixed ignored false_positive]
        severity    int     危害等级;[3 2 1 0] 高中低无危害
        '''
        path = "/vulnerabilities?q=status:{};severity:{};target_id:{}".format(status, severity, target_id)
        resp = requests.get(self.api+path, headers=self.headers)
        return resp.json()

    #按状态获取某个target的漏洞
    def get_target_vulns(self, target_id, status):
        def print_vul(vul_detail):
            vt_name, vul_level, affects_url, affects_detail, request = vul_detail
            print("*"*130)
            print("Target ID: {}\nVuln ID: {}".format(target_id, vuln_id))
            print("漏洞类型: {}".format(vt_name))
            print("危害等级: {}".format(vul_level))
            print("漏洞入口: {}".format(affects_url))
            print("漏洞参数: {}".format(affects_detail))
            print("请求包:\n{}".format(request))

        high = self.get_target_vulns_by_status_severity(target_id, status, 3)
        medium = self.get_target_vulns_by_status_severity(target_id, status, 2)
        low = self.get_target_vulns_by_status_severity(target_id, status, 1)
        info = self.get_target_vulns_by_status_severity(target_id, status, 0)

        for vuln in high.get("vulnerabilities"):
            vuln_id = vuln.get("vuln_id")

            vul_detail = self.get_single_vuln(vuln_id)
            print_vul(vul_detail)

        for vuln in medium.get("vulnerabilities"):
            vuln_id = vuln.get("vuln_id")

            vul_detail = self.get_single_vuln(vuln_id)
            print_vul(vul_detail)

        for vuln in low.get("vulnerabilities"):
            vuln_id = vuln.get("vuln_id")

            vul_detail = self.get_single_vuln(vuln_id)
            print_vul(vul_detail)

        for vuln in info.get("vulnerabilities"):
            vuln_id = vuln.get("vuln_id")

            vul_detail = self.get_single_vuln(vuln_id)
            print_vul(vul_detail)


if __name__ == "__main__":
    from pprint import pprint
    from setting import API_URL
    from setting import API_KEY

    from target import AwvsTargets
    targets = AwvsTargets(API_URL, API_KEY)
    target_id = targets.get_target_id("vulnweb.com")

    vuln = AwvsVulns(API_URL, API_KEY)
    # pprint(vuln.get_target_vulns_by_status_severity(target_id,"open",2))
    vuln.get_all_vulns(target_id, "open")
    # vuln.get_single_vuln(target_id)


