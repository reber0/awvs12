#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
@Author: reber
@Mail: reber0ask@qq.com
@Date: 2019-08-17 18:07:06
@LastEditTime: 2019-08-18 02:58:12
'''

from pprint import pprint
import json
import requests
requests.packages.urllib3.disable_warnings()

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
        resp = requests.get(self.api+path, headers=self.headers, timeout=10, verify=False)
        result = resp.json()

        script = result.get("source") #使用的脚本
        vt_name = result.get("vt_name")
        vul_level = result.get("severity")
        affects_url = result.get("affects_url")
        affects_detail = result.get("affects_detail")
        request = result.get("request")

        return vt_name, vul_level, affects_url, affects_detail, request

    #按状态和等级获取所有(不管是那个target的)的漏洞
    def get_some_vulns(self, target_id, status, severity):
        path = "/vulnerabilities?q=status:{};severity:{};target_id:{}".format(status, severity, target_id)
        resp = requests.get(self.api+path, headers=self.headers, timeout=10, verify=False)
        return resp.json()

    def get_all_vulns(self, target_id, status):
        def print_vul(vul_detail):
            vt_name, vul_level, affects_url, affects_detail, request = vul_detail
            print("*"*130)
            print("Target ID: {}\nVuln ID: {}".format(target_id, vuln_id))
            print("漏洞类型: {}".format(vt_name))
            print("危害等级: {}".format(vul_level))
            print("漏洞入口: {}".format(affects_url))
            print("漏洞参数: {}".format(affects_detail))
            print("请求包:\n{}".format(request))

        high = self.get_some_vulns(target_id, status, 3)
        medium = self.get_some_vulns(target_id, status, 2)
        low = self.get_some_vulns(target_id, status, 1)
        info = self.get_some_vulns(target_id, status, 0)

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


if __name__ == "__main__":
    from setting import API_URL
    from setting import API_KEY

    from target import AwvsTargets
    targets = AwvsTargets(API_URL, API_KEY)
    target_id = targets.get_target_id("vulnweb.com")

    vuln = AwvsVulns(API_URL, API_KEY)
    # pprint(vuln.get_some_vulns(target_id,"open",2))
    vuln.get_all_vulns(target_id, "open")
    # vuln.get_single_vuln(target_id)


