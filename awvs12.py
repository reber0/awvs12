#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
@Author: reber
@Mail: reber0ask@qq.com
@Date: 2019-08-18 02:55:39
@LastEditTime : 2020-02-25 16:53:21
'''

import sys
sys.dont_write_bytecode = True  # 不生成pyc文件

from config import API_URL
from config import API_KEY
from libs.awvs_module import AwvsModule


def main(target="http://wyb0.com"):
    awvs = AwvsModule(API_URL, API_KEY)
    awvs.start_scan(target)
    # print(awvs.get_scan_running_count())
    # awvs.abort_scan(target)
    # awvs.get_target_vuls(target)
    # awvs.download_report(target)
    # awvs.delete_scan(target)


if __name__ == "__main__":
    domain = sys.argv[1]
    main(domain)
