#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
@Author: reber
@Mail: reber0ask@qq.com
@Date: 2019-08-17 13:49:57
@LastEditTime: 2019-08-17 19:32:30
'''

from pprint import pprint
import json
import requests
requests.packages.urllib3.disable_warnings()

class AwvsScans(object):
    """docstring for AwvsScans"""
    def __init__(self, api_url, api_key):
        super(AwvsScans, self).__init__()
        self.api = api_url
        self.headers = {
            "X-Auth": api_key,
            "Content-type": "application/json; charset=utf8"
        }
        self.scan_type = {
            "FS": "11111111-1111-1111-1111-111111111111", #Full Scan
            "HR": "11111111-1111-1111-1111-111111111112", #High Risk Vulnerabilities
            "XSS": "11111111-1111-1111-1111-111111111116", #Cross-site Scripting Vulnerabilities
            "SQL": "11111111-1111-1111-1111-111111111113", #SQL Injection Vulnerabilities
            "WP": "11111111-1111-1111-1111-111111111115", #Weak Passwords
            "CO": "11111111-1111-1111-1111-111111111117" #Crawl Only
        }

    def get_all_scan_info(self):
        resp = requests.get(self.api+"/scans", headers=self.headers, timeout=10, verify=False)
        return resp.json()

    def get_single_scan_info(self, scan_id):
        path = "/scans/{}".format(scan_id)
        resp = requests.get(self.api+path, headers=self.headers, timeout=10, verify=False)
        return resp.json()

    def get_scan_and_session_id(self, target):
        scan_list = self.get_all_scan_info()
        for _ in scan_list.get("scans"):
            if target.rstrip("/") in _.get("target").get("address"):
                scan_id = _.get("scan_id")
                scan_session_id = _.get("current_session").get("scan_session_id")
                return scan_id, scan_session_id
        return None

    def add_scan(self, target_id, scan_type="FS"):
        data = json.dumps({
            "target_id": target_id,
            "profile_id": self.scan_type.get(scan_type),
            "schedule": {
                "disable": False,
                "start_date": None,
                "time_sensitive": False
            }
        })
        resp = requests.post(self.api+"/scans", data=data, headers=self.headers, timeout=10, verify=False)
        return resp.json()
    
    def delete_scan(self, scan_id):
        path = "/scans/{}".format(scan_id)
        requests.delete(self.api+path, headers=self.headers, timeout=10, verify=False)

    def get_single_vuln(self, scan_id, scan_session_id, vuln_id):
        path = "/scans/{}/results/{}/vulnerabilities/{}".format(scan_id, scan_session_id, vuln_id)
        resp = requests.get(self.api+path, headers=self.headers, timeout=10, verify=False)
        result = resp.json()

        script = result.get("source") #使用的脚本
        vt_name = result.get("vt_name")
        vul_level = result.get("severity")
        affects_url = result.get("affects_url")
        affects_detail = result.get("affects_detail")
        request = result.get("request")

        return vt_name, vul_level, affects_url, affects_detail, request

    #只能获取第一页的漏洞，漏洞数量多的话获取不完，可以用vulnerabilities模块获取
    def get_all_vuln(self, scan_id, scan_session_id):
        path = "/scans/{}/results/{}/vulnerabilities".format(scan_id, scan_session_id)
        resp = requests.get(self.api+path, headers=self.headers, timeout=10, verify=False)
        for vuln in resp.json().get("vulnerabilities"):
            vuln_id = vuln.get("vuln_id")
            # if vuln_id == "2112176097146701028":
            #     pprint(vuln)
            #     self.get_single_vuln(scan_id, scan_session_id, vuln_id)

            vul_detail = self.get_single_vuln(scan_id, scan_session_id, vuln_id)
            vt_name, vul_level, affects_url, affects_detail, request = vul_detail
            print("*"*130)
            print("Scan ID: {}\nScan Session ID: {}\nVuln ID: {}".format(scan_id, scan_session_id, vuln_id))
            print("漏洞类型: {}".format(vt_name))
            print("危害等级: {}".format(vul_level))
            print("漏洞入口: {}".format(affects_url))
            print("漏洞参数: {}".format(affects_detail))
            print("请求包:\n{}".format(request))



if __name__ == "__main__":
    from setting import API_URL
    from setting import API_KEY

    from target import AwvsTargets
    targets = AwvsTargets(API_URL, API_KEY)
    target_id = targets.get_target_id("http://test.com")

    scans = AwvsScans(API_URL, API_KEY)
    pprint(scans.get_all_scan_info())
    # pprint(scans.add_scan(target_id,"HR"))
    # scan_id, scan_session_id = scans.get_scan_and_session_id("vulnweb.com")
    # pprint(scans.get_single_scan_info(scan_id))
    # scans.delete_scan(scan_id)
    # scans.get_all_vuln(scan_id, scan_session_id)





