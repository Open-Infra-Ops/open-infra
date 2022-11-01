# -*- coding: utf-8 -*-
# @Time    : 2022/10/10 8:44
# @Author  : Tom_zc
# @FileName: views.py
# @Software: PyCharm
import json
import traceback
from datetime import datetime
from django.http import HttpResponse
from django.views import View

from clouds_tools.resources.constants import ObsInteractComment
from clouds_tools.resources.obs_interact_mgr import ObsInteractMgr, ObsInteractGitBase
from clouds_tools.resources.scan_tools import ScanPortsMgr, ScanObsMgr, SingleScanPortsMgr, SingleScanObsMgr, EipMgr, \
    HighRiskPortMgr, SlaMgr
from open_infra.utils.auth_permisson import AuthView
from open_infra.utils.common import assemble_api_result, list_param_check_and_trans
from open_infra.utils.api_error_code import ErrCode
from django.conf import settings
from logging import getLogger

from open_infra.utils.utils_git import GitHubPrStatus

logger = getLogger("django")


# noinspection DuplicatedCode,PyMethodMayBeStatic
class ScanPortView(AuthView):
    def get(self, request):
        """get all account"""
        scan_ports = ScanPortsMgr()
        clouds_account = scan_ports.get_cloud_account()
        return clouds_account

    def post(self, request):
        """output a file of scan port"""
        dict_data = json.loads(request.body)
        if dict_data.get("account") is None or not isinstance(dict_data["account"], list):
            return assemble_api_result(ErrCode.STATUS_PARAMETER_ERROR)
        logger.info("ScanPortView collect:{}".format(dict_data["account"]))
        scan_ports = ScanPortsMgr()
        content = scan_ports.query_data(dict_data["account"])
        res = HttpResponse(content=content, content_type="application/octet-stream")
        now_date = datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
        filename = settings.EXCEL_NAME.format(now_date)
        res["Content-Disposition"] = 'attachment;filename="{}"'.format(filename)
        res['charset'] = 'utf-8'
        return res


# noinspection DuplicatedCode,PyMethodMayBeStatic
class ScanObsView(AuthView):
    def get(self, request):
        """get all account"""
        scan_obs = ScanObsMgr()
        clouds_account = scan_obs.get_cloud_account()
        return clouds_account

    def post(self, request):
        """output a file of scan obs"""
        dict_data = json.loads(request.body)
        if dict_data.get("account") is None or not isinstance(dict_data["account"], list):
            return assemble_api_result(ErrCode.STATUS_PARAMETER_ERROR)
        logger.info("ScanObsView collect:{}".format(dict_data["account"]))
        scan_obs = ScanObsMgr()
        data = scan_obs.query_data(dict_data["account"])
        res = HttpResponse(content=data, content_type="application/octet-stream")
        now_date = datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
        filename = settings.SCAN_OBS_EXCEL_NAME.format(now_date)
        res["Content-Disposition"] = 'attachment;filename="{}"'.format(filename)
        res['charset'] = 'utf-8'
        return res


# noinspection DuplicatedCode,PyMethodMayBeStatic
class SingleScanPortView(AuthView):

    def post(self, request):
        """start to collect the high risk port"""
        dict_data = json.loads(request.body)
        ak = dict_data.get("ak").strip()
        sk = dict_data.get("sk").strip()
        account = dict_data.get("account").strip()
        logger.info("[SingleScanObsView] collect:{}".format(account))
        single_scan_ports = SingleScanPortsMgr()
        result = single_scan_ports.start_collect_thread(ak, sk, account)
        if result == 0:
            return assemble_api_result(ErrCode.STATUS_PARAMETER_ERROR)
        elif result == 1:
            return assemble_api_result(ErrCode.SYSTEM_BUSY)
        else:
            return assemble_api_result(ErrCode.STATUS_SUCCESS)

    def get(self, request):
        """get excel file"""
        dict_data = request.GET.dict()
        account = dict_data.get("account").strip()
        single_scan_ports = SingleScanPortsMgr()
        progress, data = single_scan_ports.query_progress(account)
        res = HttpResponse(content=data, content_type="application/octet-stream")
        if progress == 1:
            now_date = datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
            filename = settings.EXCEL_NAME.format(now_date)
            res["Content-Disposition"] = 'attachment;filename="{}"'.format(filename)
            res['charset'] = 'utf-8'
            return res
        else:
            return assemble_api_result(ErrCode.STATUS_SCAN_ING)


# noinspection DuplicatedCode,PyMethodMayBeStatic
class SingleScanObsView(AuthView):

    def post(self, request):
        """start to collect the sensitive data of obs """
        dict_data = json.loads(request.body)
        ak = dict_data.get("ak").strip()
        sk = dict_data.get("sk").strip()
        account = dict_data.get("account").strip()
        logger.info("[SingleScanObsView] collect:{}".format(account))
        single_scan_obs = SingleScanObsMgr()
        result = single_scan_obs.start_collect_thread(ak, sk, account)
        if result == 0:
            return assemble_api_result(ErrCode.STATUS_PARAMETER_ERROR)
        elif result == 1:
            return assemble_api_result(ErrCode.SYSTEM_BUSY)
        else:
            return assemble_api_result(ErrCode.STATUS_SUCCESS)

    def get(self, request):
        """get excel file"""
        dict_data = request.GET.dict()
        account = dict_data.get("account").strip()
        single_scan_obs = SingleScanObsMgr()
        progress, data = single_scan_obs.query_progress(account)
        if progress == 0:
            return assemble_api_result(ErrCode.STATUS_SCAN_ING)
        elif progress == 1:
            res = HttpResponse(content=data, content_type="application/octet-stream")
            now_date = datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
            filename = settings.SCAN_OBS_EXCEL_NAME.format(now_date)
            res["Content-Disposition"] = 'attachment;filename="{}"'.format(filename)
            res['charset'] = 'utf-8'
            return res
        else:
            return assemble_api_result(ErrCode.STATUS_SCAN_FAILED)


# noinspection DuplicatedCode,PyMethodMayBeStatic
class PortsListView(AuthView):
    def get(self, request):
        """get the port list"""
        params_dict = list_param_check_and_trans(request.GET.dict(), order_type="1", order_by="port")
        port_mgr = HighRiskPortMgr()
        data = port_mgr.list(params_dict)
        return assemble_api_result(ErrCode.STATUS_SUCCESS, data=data)

    def post(self, request):
        """create the port"""
        dict_data = json.loads(request.body)
        port = dict_data.get("port").strip()
        desc = dict_data.get("desc").strip()
        if not port.isdigit() or len(desc) > 255:
            logger.info("valid port:{} or desc:{}".format(port, desc))
            return assemble_api_result(ErrCode.STATUS_PARAMETER_ERROR)
        try:
            port = int(port)
        except ValueError as e:
            logger.error("port is valid:{}, e:{}".format(port, e))
            return assemble_api_result(ErrCode.STATUS_PARAMETER_ERROR)
        port_mgr = HighRiskPortMgr()
        ret = port_mgr.create(port, desc)
        if ret == 0:
            return assemble_api_result(ErrCode.STATUS_SUCCESS)
        else:
            return assemble_api_result(ErrCode.STATUS_PORT_EXIST)


# noinspection DuplicatedCode,PyMethodMayBeStatic
class PortsListDeleteView(AuthView):
    def post(self, request):
        """batch delete the high risk of port"""
        dict_data = json.loads(request.body)
        port_list = dict_data.get("port_list")
        logger.info("[PortsListDeleteView] receive data:{}".format(port_list))
        if not isinstance(port_list, list):
            return ErrCode.STATUS_PARAMETER_ERROR
        port_mgr = HighRiskPortMgr()
        port_mgr.delete(port_list)
        return assemble_api_result(ErrCode.STATUS_SUCCESS)


# noinspection DuplicatedCode,PyMethodMayBeStatic
class EipView(AuthView):
    def get(self, request):
        """get the list of eip"""
        params_dict = list_param_check_and_trans(request.GET.dict())
        eip_mgr = EipMgr()
        data = eip_mgr.list_eip(params_dict)
        return assemble_api_result(ErrCode.STATUS_SUCCESS, data=data)


# noinspection DuplicatedCode,PyMethodMayBeStatic
class ServiceView(AuthView):
    def get(self, request):
        """get the list of serive"""
        params_dict = list_param_check_and_trans(request.GET.dict(), order_by="create_time")
        sla_mgr = SlaMgr()
        data = sla_mgr.list(params_dict)
        return assemble_api_result(ErrCode.STATUS_SUCCESS, data=data)


# noinspection DuplicatedCode,PyMethodMayBeStatic
class SlaExportView(AuthView):
    def get(self, request):
        """get the file excel of sla"""
        sla_mgr = SlaMgr()
        data = sla_mgr.export()
        res = HttpResponse(content=data, content_type="application/octet-stream")
        now_date = datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
        filename = settings.CLA_EXCEL_NAME.format(now_date)
        res["Content-Disposition"] = 'attachment;filename="{}"'.format(filename)
        res['charset'] = 'utf-8'
        return res


# noinspection PyMethodMayBeStatic
class ObsInteractView(View):

    def post(self, request):
        """the api for github obs-interact"""
        dict_data = json.loads(request.body)
        if not GitHubPrStatus.is_in_github_pr_status(dict_data.get("action")):
            logger.error("[GitHubPrView] receive param fault:{}".format(dict_data.get("action")))
            return assemble_api_result(err_code=ErrCode.STATUS_SUCCESS)
        obs_interact_git_base = ObsInteractGitBase(dict_data)
        try:
            ObsInteractMgr.get_obs_interact(obs_interact_git_base)
        except Exception as e:
            logger.error("[GitHubPrView] e:{}, traceback:{}".format(e, traceback.format_exc()))
            obs_interact_git_base.comment_pr(comment=ObsInteractComment.error)
        return assemble_api_result(err_code=ErrCode.STATUS_SUCCESS)
