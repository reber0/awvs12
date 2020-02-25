#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
@Author: reber
@Mail: reber0ask@qq.com
@Date: 2019-08-18 02:55:39
@LastEditTime : 2020-02-25 22:47:02
'''

import sys
sys.dont_write_bytecode = True  # 不生成pyc文件

from pprint import pprint
from libs.awvs_module import AwvsModule

def print_vuln(target_id, vuln_id, vuln_detail):
    vt_name, vul_level, affects_url, affects_detail, request = vuln_detail
    print("*"*130)
    print("Target ID: {}\nVuln ID: {}".format(target_id, vuln_id))
    print("漏洞类型: {}".format(vt_name))
    print("危害等级: {}".format(vul_level))
    print("漏洞入口: {}".format(affects_url))
    print("漏洞参数: {}".format(affects_detail))
    print("请求包:\n{}".format(request))


def main(target="http://wyb0.com", api_url=None, api_key=None):
    awvs = AwvsModule(api_url, api_key)

    # 开始扫描
    # awvs.start_scan(target)

    # 获取当前扫描任务数
    # dashboard_stats = awvs.get_stats()
    # scans_running_count = dashboard_stats.get("scans_running_count")
    # pprint(scans_running_count)

    # 暂停扫描
    # awvs.abort_scan(target)

    # 获取漏洞详情
    # target_id, vuln_list_detail = awvs.get_target_vuls(target)
    # for vuln_id, vuln_detail in vuln_list_detail.items():
    #     print_vuln(target_id, vuln_id, vuln_detail)

    # 下载漏洞报告
    # awvs.download_report(target)

    # 删除扫描任务
    # awvs.delete_scan(target)


if __name__ == "__main__":
    from config import API_URL
    from config import API_KEY

    domain = sys.argv[1]
    main(domain, API_URL, API_KEY)
