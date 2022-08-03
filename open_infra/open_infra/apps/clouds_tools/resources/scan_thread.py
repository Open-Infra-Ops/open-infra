# -*- coding: utf-8 -*-
# @Time    : 2022/7/28 11:27
# @Author  : Tom_zc
# @FileName: scan_thread.py
# @Software: PyCharm
import os
from django.conf import settings
from clouds_tools.resources.scan_tools import ScanPortInfo, ScanObsInfo, ScanObsStatus, LockObj, ScanBaseTools, \
    ScanPortStatus
from open_infra.utils.scan_port import single_scan_port
from open_infra.utils.scan_obs import single_scan_obs
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
        ScanPortInfo.clear()
        # now_account_info_list = ScanBaseTools.get_cloud_config()
        # for config_item in now_account_info_list:
        #     ak = config_item["ak"]
        #     sk = config_item["sk"]
        #     project_list = config_item["project_info"]
        #     for project_info in project_list:
        #         project_id = project_info.get("project_id")
        #         zone = project_info.get("zone")
        #         key = (ak, sk, project_id, zone)
        #         single_scan_port_info = ScanPortInfo.get(key)
        #         if single_scan_port_info is not None:
        #             continue
        #         ScanPortInfo.set({key: {"status": ScanPortStatus.new, "data": dict()}})
        #         tcp_ret_dict, udp_ret_dict, tcp_server_info = single_scan_port(ak, sk, zone, project_id)
        #         dict_data = {
        #             "tcp_info": tcp_ret_dict,
        #             "udp_info": udp_ret_dict,
        #             "tcp_server_info": tcp_server_info
        #         }
        #         logger.info("[ScanThreadTools] scan_port: key:({},{},{},{}), data:{}".format(ak[0:5], sk[0:5], project_id, zone, dict_data))
        #         ScanPortInfo.set({key: {"status": ScanPortStatus.finish, "data": dict_data}})
        # logger.info("----------------finish scan_port-----------------------")

    @classmethod
    def scan_obs(cls):
        ScanObsInfo.clear()
        # now_account_info_list = ScanBaseTools.get_cloud_config()
        # for config_item in now_account_info_list:
        #     ak = config_item["ak"]
        #     sk = config_item["sk"]
        #     account = config_item["account"]
        #     key = (ak, sk, account)
        #     single_scan_obs_info = ScanObsInfo.get(key)
        #     if single_scan_obs_info is not None:
        #         continue
        #     ScanObsInfo.set({key: {"status": ScanObsStatus.new, "data": dict()}})
        #     file_list, bucket_list, data_list = single_scan_obs(ak, sk, account)
        #     dict_data = {
        #         "anonymous_file": file_list or [],
        #         "anonymous_bucket": bucket_list or [],
        #         "anonymous_data": data_list or []
        #     }
        #     logger.info("[ScanThreadTools] scan_obs:({},{},{}),data：{}".format(ak[0:5], sk[0:5], account, dict_data))
        #     ScanObsInfo.set({key: {"status": ScanObsStatus.finish, "data": dict_data}})
        # logger.info("----------------finish scan_obs-----------------------")
