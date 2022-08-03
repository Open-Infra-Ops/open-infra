# -*- coding: utf-8 -*-
# @Time    : 2022/7/21 15:34
# @Author  : Tom_zc
# @FileName: scan_tools.py
# @Software: PyCharm
import traceback
from functools import wraps

from open_infra.libs.obs_utils import ObsLib, HuaweiCloud
from open_infra.utils.common import output_scan_port_excel, output_scan_obs_excel
from open_infra.utils.lock_util import RWLock
from open_infra.utils.scan_port import single_scan_port
from open_infra.utils.scan_obs import single_scan_obs
from django.conf import settings
from threading import Thread, Lock
from collections import defaultdict
from logging import getLogger
from open_infra.utils.scan_port import EipTools as ScanPortEipTools
from open_infra.utils.scan_obs import EipTools as ScanObsEipTools

logger = getLogger("django")


class LockObj(object):
    cloud_config = Lock()
    scan_port_rw_lock = RWLock()
    scan_obs_rw_lock = RWLock()


class BaseStatus(object):
    new = 0
    handler = 1
    finish = 2


class ScanPortStatus(BaseStatus):
    pass


class ScanObsStatus(BaseStatus):
    pass


class BaseInfo(object):
    _lock = Lock()
    _data = defaultdict(dict)

    @classmethod
    def set(cls, dict_data):
        with cls._lock:
            cls._data.update(dict_data)

    @classmethod
    def get(cls, key):
        with cls._lock:
            return cls._data.get(key)

    @classmethod
    def clear(cls):
        with cls._lock:
            cls._data = defaultdict(dict)

    @classmethod
    def delete_key(cls, key):
        with cls._lock:
            if key in cls._data.keys():
                del cls._data[key]


class ScanPortInfo(BaseInfo):
    pass


class ScanObsInfo(BaseInfo):
    pass


# noinspection PyArgumentList
class ScanBaseTools(object):
    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = object.__new__(cls, *args, **kwargs)
        return cls._instance

    def __init__(self, *args, **kwargs):
        pass

    @staticmethod
    def get_project_info(ak, sk):
        return HuaweiCloud.get_project_zone(ak, sk)

    def query_data(self, account_list):
        raise NotImplemented()


class SingleScanPorts(ScanBaseTools):

    @staticmethod
    def collect_thread(ak, sk, zone, project_id):
        """collect data"""
        tcp_ret_dict, udp_ret_dict, tcp_server_info = single_scan_port(ak, sk, zone, project_id)
        dict_data = {
            "tcp_info": tcp_ret_dict,
            "udp_info": udp_ret_dict,
            "tcp_server_info": tcp_server_info
        }
        key = (ak, sk, project_id, zone)
        logger.info("[collect_thread] collect single scan port: key:({}, {}, {}, {}), data:{}".format(ak[:5], sk[:5],
                                                                                                      project_id, zone,
                                                                                                      dict_data))
        ScanPortInfo.set({key: {"status": ScanPortStatus.finish, "data": dict_data}})

    def start_collect_thread(self, ak, sk):
        """start a collect thread"""
        eip_tools = ScanPortEipTools()
        try:
            project_info = ScanBaseTools.get_project_info(ak, sk)
            if not project_info:
                raise Exception("[start_collect_thread] Get empty project info, Failed")
            for project_obj in project_info:
                eip_tools.get_data_list(project_obj["project_id"], project_obj["zone"], ak, sk)
                break
        except Exception as e:
            logger.error("[start_collect_thread] connect:{}, {}".format(e, traceback.format_exc()))
            return False
        for project_obj in project_info:
            try:
                # 1.judge status
                project_id = project_obj["project_id"]
                zone = project_obj["zone"]
                key = (ak, sk, project_id, zone)
                single_scan_port_info = ScanPortInfo.get(key)
                if single_scan_port_info is not None:
                    continue
                ScanPortInfo.set({key: {"status": ScanPortStatus.new, "data": dict()}})
                # 2.start a thread to collect data
                th = Thread(target=self.collect_thread, args=(ak, sk, zone, project_id))
                th.start()
                # 3.set status to handler
                ScanPortInfo.set({key: {"status": ScanPortStatus.handler, "data": dict()}})
            except Exception as e:
                logger.error(
                    "[start_collect_thread] collect data failed:{}, traceback:{}".format(e, traceback.format_exc()))
        return True

    # noinspection PyMethodMayBeStatic
    def query_progress(self, ak, sk):
        """query progress"""
        tcp_info, udp_info, tcp_server_info = dict(), dict(), dict()
        content = str()
        project_info = ScanBaseTools.get_project_info(ak, sk)
        if not project_info:
            return 0, content
        for project_obj in project_info:
            project_id = project_obj["project_id"]
            zone = project_obj["zone"]
            key = (ak, sk, project_id, zone)
            single_scan_port_info = ScanPortInfo.get(key)
            if single_scan_port_info is not None and single_scan_port_info["status"] == ScanObsStatus.handler:
                return 0, content
            elif single_scan_port_info is not None and single_scan_port_info["status"] == ScanPortStatus.finish:
                tcp_info.update(single_scan_port_info["data"]["tcp_info"])
                udp_info.update(single_scan_port_info["data"]["udp_info"])
                tcp_server_info.update(single_scan_port_info["data"]["tcp_server_info"])
        content = output_scan_port_excel(tcp_info, udp_info, tcp_server_info)
        return 1, content


class SingleScanObs(ScanBaseTools):
    _lock = Lock()

    @staticmethod
    def collect_thread(ak, sk, account):
        """collect data"""
        list_sensitive_file, list_anonymous_bucket, list_anonymous_data = single_scan_obs(ak, sk, account)
        dict_data = {
            "anonymous_file": list_sensitive_file or [],
            "anonymous_bucket": list_anonymous_bucket or [],
            "anonymous_data": list_anonymous_data or []
        }
        key = (ak, sk, account)
        logger.info("[SingleScanObs] collect single scan_obs: key({},{},{}), data:{}".format(ak[:5], sk[:5], account,
                                                                                             dict_data))
        ScanObsInfo.set({key: {"status": ScanObsStatus.finish, "data": dict_data}})

    def start_collect_thread(self, ak, sk, account):
        """start a collect thread"""
        try:
            eip_tools = ScanObsEipTools()
            eip_tools.get_all_bucket(ak, sk, settings.OBS_BASE_URL, inhibition_fault=False)
        except Exception as e:
            logger.error("[SingleScanObs] start_collect_thread connect:{}, {}".format(e, traceback.format_exc()))
            return False
        key = (ak, sk, account)
        # 1.judge status
        single_scan_obs_info = ScanObsInfo.get(key)
        if single_scan_obs_info is not None:
            return True
        ScanObsInfo.set({key: {"status": ScanObsStatus.new, "data": dict()}})
        # 2.start a thread to collect data
        th = Thread(target=self.collect_thread, args=(ak, sk, account))
        th.start()
        # 3.set status to handler
        ScanObsInfo.set({key: {"status": ScanObsStatus.handler, "data": dict()}})
        return True

    # noinspection PyMethodMayBeStatic
    def query_progress(self, ak, sk, account):
        """query progress"""
        content = str()
        key = (ak, sk, account)
        logger.info("now collect obs data:{}".format(key))
        single_scan_obs_info = ScanObsInfo.get(key)
        if single_scan_obs_info is not None and single_scan_obs_info["status"] == ScanObsStatus.handler:
            return 0, content
        if single_scan_obs_info is not None and single_scan_obs_info["status"] == ScanObsStatus.finish:
            anonymous_file_list = single_scan_obs_info["data"]["anonymous_file"]
            anonymous_bucket_list = single_scan_obs_info["data"]["anonymous_bucket"]
            anonymous_data_data = single_scan_obs_info["data"]["anonymous_data"]
            content = output_scan_obs_excel(anonymous_file_list, anonymous_bucket_list, anonymous_data_data)
            return 1, content
        else:
            logger.info("single scan obs query_progress query no result")
            return 2, content
