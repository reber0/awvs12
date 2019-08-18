#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
@Author: reber
@Mail: reber0ask@qq.com
@Date: 2019-08-17 19:40:58
@LastEditTime: 2019-08-18 19:04:17
'''

import time
from pprint import pprint
from urllib.parse import urlparse
import json
import requests
requests.packages.urllib3.disable_warnings()

from api.scans import AwvsScans

class AwvsReports(object):
    """docstring for AwvsReports"""
    def __init__(self, api_url, api_key):
        super(AwvsReports, self).__init__()
        self.api = api_url
        self.headers = {
            "X-Auth": api_key,
            "Content-type": "application/json; charset=utf8"
        }
        self.template_type = {
            "AI": "11111111-1111-1111-1111-111111111115",   #Affected Items
            "C2": "11111111-1111-1111-1111-111111111116",   #CWE 2011
            "D": "11111111-1111-1111-1111-111111111111",    #Developer
            "ES": "11111111-1111-1111-1111-111111111113",   #Executive Summary
            "H": "11111111-1111-1111-1111-111111111114",    #HIPAA
            "I2": "11111111-1111-1111-1111-111111111117",   #ISO 27001
            "NS5": "11111111-1111-1111-1111-111111111118",  #NIST SP800 53
            "OT12": "11111111-1111-1111-1111-111111111119", #OWASP Top 10 2013
            "PD3": "11111111-1111-1111-1111-111111111120",  #PCI DSS 3.2
            "Q": "11111111-1111-1111-1111-111111111112",    #Quick
            "SO": "11111111-1111-1111-1111-111111111121",   #Sarbanes Oxley
            "SC": "11111111-1111-1111-1111-111111111124",   #Scan Comparison
            "SD": "11111111-1111-1111-1111-111111111122",   #STIG DISA
            "WTC": "11111111-1111-1111-1111-111111111123",  #WASC Threat Classification
        }
        self.scans = AwvsScans(api_url, api_key)
    
    def get_all_report(self):
        resp = requests.get(self.api+"/reports", headers=self.headers, timeout=10, verify=False)
        return resp.json()

    def create_report(self, template_type, scan_id):
        scans_info = self.scans.get_single_scan_info(scan_id)
        scan_status = scans_info.get("current_session").get("status")
        if scan_status != "completed":
            return (scan_status, None)
        else:
            data = json.dumps({
                "template_id": self.template_type.get(template_type),
                "source":{
                    "list_type":"scans",
                    "id_list":[scan_id]
                }
            })
            resp = requests.post(self.api+"/reports", data=data, headers=self.headers, timeout=10, verify=False)
            report_id = resp.headers.get("Location").replace("/api/v1/reports/","")
            return ("completed", report_id)
    
    def download_report(self, report_id):
        path = "/reports/{}".format(report_id)
        requests.get(self.api+path, headers=self.headers, timeout=10, verify=False)

        while True:
            time.sleep(3)
            resp = requests.get(self.api+path, headers=self.headers, timeout=10, verify=False)
            result = resp.json()
            if result.get("status") == "completed":
                target = result.get("source").get("description")
                date = result.get("generation_date")[:10].replace("-","_")+"_"
                template_name = result.get("template_name").replace(" ","_")+"_"

                filename = date+template_name+urlparse(target).netloc.replace(".","_")+".pdf"
                download_url = self.api+result.get("download")[1].replace("/api/v1", "")

                with open("./reports/"+filename, "wb") as f:
                    resp = requests.get(download_url, headers=self.headers, timeout=10, verify=False)
                    f.write(resp.content)
                break


if __name__ == "__main__":
    from setting import API_URL
    from setting import API_KEY

    from scans import AwvsScans
    scans = AwvsScans(API_URL, API_KEY)
    scan_id, scan_session_id = scans.get_scan_and_session_id("vulnweb.com")

    reports = AwvsReports(API_URL, API_KEY)
    pprint(reports.get_all_report())
    # report_id = reports.create_report("AI",scan_id)
    # reports.download_report(report_id)

