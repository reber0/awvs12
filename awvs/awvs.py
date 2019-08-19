#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
@Author: reber
@Mail: reber0ask@qq.com
@Date: 2019-08-18 02:55:39
@LastEditTime: 2019-08-18 19:03:09
'''

import sys
sys.dont_write_bytecode = True  # 不生成pyc文件

from pprint import pprint
from api.targets import AwvsTargets
from api.scans import AwvsScans
from api.vulns import AwvsVulns
from api.reports import AwvsReports
from setting import API_URL
from setting import API_KEY

class AwvsModule(object):
    """docstring for AwvsModule"""
    def __init__(self, API_URL, API_KEY):
        super(AwvsModule, self).__init__()
        self.api_url = API_URL
        self.api_key = API_KEY
        self.targets = AwvsTargets(self.api_url, self.api_key)
        self.scans = AwvsScans(self.api_url, self.api_key)
        self.vulns = AwvsVulns(self.api_url, self.api_key)
        self.reports = AwvsReports(self.api_url, self.api_key)

    def add_target(self, target, criticality="10", description="awvs_scan"):
        self.targets.add_target(target, criticality, description)

    def delete_target(self, target):
        target_id = self.targets.get_target_id(target)
        self.targets.delete_target(target_id)

    def add_scan(self, target, scan_type="FS"):
        target_id = self.targets.get_target_id(target)
        self.scans.add_scan(target_id, scan_type)

    def abort_scan(self, target):
        scan_id, scan_session_id = self.scans.get_scan_and_session_id(target)
        self.scans.abort_scan(scan_id)

    def delete_scan(self, target):
        scan_id, scan_session_id = self.scans.get_scan_and_session_id(target)
        self.scans.delete_scan(scan_id)

    def get_vulns(self, target, status="open"):
        target_id = self.targets.get_target_id(target)
        self.vulns.get_all_vulns(target_id, status)

    def download_report(self, target, template_type="AI"):
        scan_id, scan_session_id = self.scans.get_scan_and_session_id(target)
        scan_status, report_id = self.reports.create_report(template_type, scan_id)
        if report_id:
            self.reports.download_report(report_id)
        else:
            print("扫描状态不是 completed，是 {}，不能导出报告！".format(scan_status))


if __name__ == "__main__":
    target = sys.argv[1]
    awvs = AwvsModule(API_URL, API_KEY)
    awvs.add_target(target)
    # awvs.delete_target(target)
    # awvs.add_scan(target)
    # awvs.abort_scan(target)
    # awvs.delete_scan(target)
    # awvs.get_vulns(target)
    # awvs.download_report(target)
