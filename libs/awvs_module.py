#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
@Author: reber
@Mail: reber0ask@qq.com
@Date: 2019-08-18 02:55:39
@LastEditTime : 2020-02-25 22:08:07
'''

try:
    from api.reports import AwvsReports
    from api.vulns import AwvsVulns
    from api.scans import AwvsScans
    from api.targets import AwvsTargets
    from api.dashboard import AwvsDashboard
except ModuleNotFoundError:
    from awvs12.api.reports import AwvsReports
    from awvs12.api.vulns import AwvsVulns
    from awvs12.api.scans import AwvsScans
    from awvs12.api.targets import AwvsTargets
    from awvs12.api.dashboard import AwvsDashboard


class AwvsModule(object):
    """docstring for AwvsModule"""

    def __init__(self, API_URL, API_KEY):
        super(AwvsModule, self).__init__()
        self.api_url = API_URL
        self.api_key = API_KEY
        self.dashboard = AwvsDashboard(self.api_url, self.api_key)
        self.targets = AwvsTargets(self.api_url, self.api_key)
        self.scans = AwvsScans(self.api_url, self.api_key)
        self.vulns = AwvsVulns(self.api_url, self.api_key)
        self.reports = AwvsReports(self.api_url, self.api_key)

    def start_scan(self, target=None, criticality="10", description="awvs_scan", scan_type="FS"):
        """
        这里有两步操作，先添加 target，然后添加 scan
        """
        target_info = self.targets.add_target(target, criticality, description)
        target_id = target_info.get("target_id")

        self.scans.add_scan(target_id, scan_type)

        # 查看 scan 是否创建成功，成功返回 True
        all_scan_info = self.scans.get_all_scan_info()
        for scan_info in all_scan_info.get("scans"):
            if target_id == scan_info.get("target_id"):
                scan_id = scan_info.get("scan_id")
                scan_session_id = scan_info.get(
                    "current_session").get("scan_session_id")
                if scan_id and scan_session_id:
                    return scan_id, scan_session_id

    def get_scan_running_count(self):
        dashboard_stats = self.dashboard.stats()
        return dashboard_stats.get("scans_running_count")

    def get_target_vuls(self, target):
        target_id = self.targets.get_target_id(target)
        scan_id, scan_session_id = self.scans.get_scan_and_session_id(target)
        target_id, vuln_list_detail = self.vulns.get_target_vulns(target_id, status="open")

        return target_id, vuln_list_detail

    def delete_scan(self, target):
        """
        这里的 delete_scan 其实是delete target，
        因为 target 被删除时该 target 下所有的 scan 都会被删除
        """
        target_id = self.targets.get_target_id(target)
        self.targets.delete_target(target_id)

    def abort_scan(self, target):
        scan_id, scan_session_id = self.scans.get_scan_and_session_id(target)
        self.scans.abort_scan(scan_id)

    def download_report(self, target, template_type="AI"):
        scan_id, scan_session_id = self.scans.get_scan_and_session_id(target)
        scan_status, report_id = self.reports.create_report(
            template_type, scan_id)
        if report_id:
            self.reports.download_report(report_id)
        else:
            print("扫描状态不是 completed，是 {}，不能导出报告！".format(scan_status))


if __name__ == "__main__":
    from pprint import pprint
    from config import API_KEY
    from config import API_URL

    target = sys.argv[1]
    awvs = AwvsModule(API_URL, API_KEY)
    # awvs.start_scan(target)
    # print(awvs.get_scan_running_count())
    # awvs.abort_scan(target)
    # awvs.get_target_vuls(target)
    # awvs.download_report(target)
    # awvs.delete_scan(target)
