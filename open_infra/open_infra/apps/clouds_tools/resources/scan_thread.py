# -*- coding: utf-8 -*-
# @Time    : 2022/7/28 11:27
# @Author  : Tom_zc
# @FileName: scan_thread.py
# @Software: PyCharm
import os
from django.conf import settings
from clouds_tools.resources.scan_tools import ScanPortInfo, ScanObsInfo, LockObj
from logging import getLogger

logger = getLogger("django")


class ScanThreadTools(object):
    @classmethod
    def clear_yaml(cls):
        with LockObj.cloud_config:
            full_path = os.path.join(settings.LIB_PATH, "collect_elastic_public_ip.yaml")
            if os.path.exists(full_path):
                os.remove(full_path)

    @classmethod
    def scan_port(cls):
        # todo 这里需要和查询进行互斥处理，暂时没有想好，不处理
        ScanPortInfo.clear()

    @classmethod
    def scan_obs(cls):
        ScanObsInfo.clear()
