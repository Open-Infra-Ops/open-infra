# -*- coding: utf-8 -*-
# @Time    : 2022/7/28 11:27
# @Author  : Tom_zc
# @FileName: scan_thread.py
# @Software: PyCharm
from threading import Lock
from open_infra.utils.common import BaseStatus


class HWCloudEipStatus(BaseStatus):
    """Eip Status"""
    FREEZED = (0, "冻结")
    BIND_ERROR = (1, "绑定失败")
    BINDING = (2, "绑定中")
    PENDING_CREATE = (3, "创建中")
    PENDING_DELETE = (4, "释放中")
    PENDING_UPDATE = (5, "更新中")
    NOTIFYING = (6, "通知绑定中")
    NOTIFY_DELETE = (7, "通知释放中")
    DOWN = (8, "未绑定")
    ACTIVE = (9, "绑定")
    ELB = (10, "绑定ELB")
    VPN = (11, "绑定VPN")
    ERROR = (12, "失败")


class HWCloudEipType(BaseStatus):
    """Eip Type"""
    EIP = (0, "全动态BGP")


class NetProtocol(object):
    """Network  Protocol"""
    TCP = 1
    UDP = 0


class ScanBaseStatus(object):
    """the scan base status"""
    handler = 1
    finish = 2


class ScanPortStatus(ScanBaseStatus):
    pass


class ScanObsStatus(ScanBaseStatus):
    pass


class ScanToolsLock:
    """the all lock about app clouds tools"""
    scan_port = Lock()
    scan_obs = Lock()
    refresh_service_info_lock = Lock()
    obs_interact_lock = Lock()


class ObsInteractComment(object):
    """The Obs Interact of comment"""
    error = "The internal service is abnormal, Please contact the warehouse administrator."
    welcome = """Hi ***{}***, welcome to the Open-Infra-Ops Community.\nI'm the Bot here serving you.Thank you for submitting the obs request.\nApplication check result: ***{}***.\nDetail: {}"""
    lgtm = """Hi ***{}***, Thank you for your application. The information about your application has been sent to you by email, please check it carefully."""
    valid_lgtm = "Hi, lgtm should be confirmed by the repository administrator: {}."
    check_upload_false = """Hi ***{}***,Unfortunately, the file you uploaded did not pass the inspection, And the reason for the failure to pass the inspection:\n{}"""
    check_upload_ok = """Hi ***{}***,Congratulations, the uploaded file passed the inspection successfully, this PR request will be closed automatically"""


class Community(BaseStatus):
    """The all community"""
    INFRA = (0, "infra")
    MINDSPORE = (1, "mindspore")
    OPENGUASS = (2, "opengauss")
    OPENEULER = (3, "openeuler")
    OPENLOOKENG = (4, "openlookeng")

    @classmethod
    def is_in_community(cls, community):
        """judge community is in this community"""
        dict_data = cls.get_comment_status()
        if community in dict_data.keys():
            return True
        else:
            return False


class ClousToolsGlobalConfig:
    """The clouds tools of global config"""
    service_txt_url = "https://api.github.com/repos/Open-Infra-Ops/kubeconfig-community/contents/doc/ServiceName.txt"
