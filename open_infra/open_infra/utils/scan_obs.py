# -*- coding: utf-8 -*-
# @Time    : 2022/7/25 19:55
# @Author  : Tom_zc
# @FileName: scan_obs.py
# @Software: PyCharm
import json
import argparse
import yaml
import traceback
from collections import defaultdict
from obs.client import ObsClient
from cocoNLP.extractor import extractor
from django.conf import settings
from logging import getLogger

logger = getLogger("django")


# noinspection DuplicatedCode
class EipTools(object):
    _ex = extractor()

    def __init__(self, *args, **kwargs):
        super(EipTools, self).__init__(*args, **kwargs)

    @classmethod
    def output_txt(cls, path, eip_info_list):
        with open(path, "w", encoding="utf-8") as f:
            for content in eip_info_list:
                f.write(content)
                f.write("\n")

    @classmethod
    def parse_input_args(cls):
        par = argparse.ArgumentParser()
        par.add_argument("-config_path", "--config_path", help="The config path of object", required=False)
        args = par.parse_args()
        return args

    @staticmethod
    def load_yaml(file_path, method="load"):
        """
        method: load_all/load
        """
        yaml_load_method = getattr(yaml, method)
        with open(file_path, "r", encoding="utf-8") as file:
            content = yaml_load_method(file, Loader=yaml.FullLoader)
        return content

    @classmethod
    def check_config_data(cls, config_list):
        for config_temp in config_list:
            if config_temp.get("account") is None:
                raise Exception("Account is invalid")
            if config_temp.get("ak") is None:
                raise Exception("Ak is invalid")
            if config_temp.get("sk") is None:
                raise Exception("Sk is invalid")

    @classmethod
    def get_bucket_acl(cls, obs_client, bucket_name):
        if not isinstance(obs_client, ObsClient):
            raise Exception("obs_client must be instantiated")
        list_result = list()
        try:
            resp = obs_client.getBucketAcl(bucket_name)
            if resp.status < 300:
                for grant in resp.body.grants:
                    list_result.append(dict(grant))
            else:
                logger.info('get_bucket_acl:errorCode:', resp.errorCode)
                logger.info('get_bucket_acl:errorMessage:', resp.errorMessage)
        except Exception as e:
            logger.info("get_bucket_acl:{}, traceback:{}".format(e, traceback.format_exc()))
        return list_result

    @classmethod
    def get_bucket_policy(cls, obs_client, bucket_name):
        if not isinstance(obs_client, ObsClient):
            raise Exception("obs_client must be instantiated")
        try:
            resp = obs_client.getBucketPolicy(bucket_name)
            if resp.status < 300:
                return resp.body.policyJSON
            elif resp.errorCode == "NoSuchBucketPolicy":
                return None
            else:
                logger.info('get_bucket_bucket:errorCode:', resp.errorCode)
                logger.info('get_bucket_bucket:errorMessage:', resp.errorMessage)
        except Exception as e:
            logger.info("get_bucket_acl:{}, traceback:{}".format(e, traceback.format_exc()))
        return None

    @classmethod
    def get_bucket_obj(cls, obs_client, bucket_name):
        if not isinstance(obs_client, ObsClient):
            raise Exception("obs_client must be instantiated")
        list_result = list()
        try:
            resp = obs_client.listObjects(bucket_name, max_keys=100000)
            if resp.status < 300:
                for content in resp.body.contents:
                    list_result.append(content)
            else:
                logger.info('get_bucket_obj:errorCode:', resp.errorCode)
                logger.info('get_bucket_obj:errorMessage:', resp.errorMessage)
        except Exception as e:
            logger.info("get_bucket_obj:{}, traceback:{}".format(e, traceback.format_exc()))
        return list_result

    @classmethod
    def download_obs_data(cls, obs_client, bucket_name, obs_key):
        """download obs data"""
        content = str()
        resp = obs_client.getObject(bucket_name, obs_key, loadStreamInMemory=False)
        if resp.status < 300:
            try:
                while True:
                    chunk = resp.body.response.read(65536)
                    if not chunk:
                        break
                    content = "{}{}".format(content, chunk.decode("utf-8"))
            except Exception:
                pass
            resp.body.response.close()
        elif resp.errorCode == "NoSuchKey":
            logger.info("Key:{} is not exist, need to create".format(obs_key))
        else:
            logger.info('errorCode:', resp.errorCode)
            logger.info('errorMessage:', resp.errorMessage)
            raise Exception("get object failed：{}....".format(obs_key))
        return content

    # noinspection PyBroadException
    @classmethod
    def get_sensitive_data(cls, content):
        sensitive_dict_data = dict()
        # try:
        #     name = cls._ex.extract_name(content)
        #     if name:
        #         sensitive_dict_data["name"] = name
        # except Exception:
        #     pass
        sensitive_email = cls._ex.extract_email(content)
        sensitive_phone = cls._ex.extract_cellphone(content, nation='CHN')
        if sensitive_email:
            sensitive_dict_data["email"] = sensitive_email
        if sensitive_phone:
            sensitive_dict_data["phone_number"] = sensitive_phone
        return sensitive_dict_data

    @classmethod
    def check_bucket_info(cls, obs_client, bucket_name, account, zone):
        list_result, list_anonymous_bucket, list_anonymous_data = list(), list(), list()
        is_anonymous = False

        # first to judge bucket policy
        policy_content = cls.get_bucket_policy(obs_client, bucket_name)
        if policy_content:
            policy_obj = json.loads(policy_content)
            for statement_info in policy_obj["Statement"]:
                if statement_info.get("Principal") is not None and r"*" in statement_info["Principal"]["ID"]:
                    is_anonymous = True
                    break
        # second to judge bucket acl
        if not is_anonymous:
            acl_list = cls.get_bucket_acl(obs_client, bucket_name)
            for acl_info in acl_list:
                group_info = acl_info["grantee"].get("group")
                if group_info is not None and acl_info["grantee"]["group"] == "Everyone":
                    is_anonymous = True
                    break
        if is_anonymous:
            logger.info("collect account:{}, bucket_name:{}".format(account, bucket_name))
            bucket_url = settings.OBS_BUCKET_URL.format(bucket_name, zone)
            list_anonymous_bucket.append([account, bucket_name, bucket_url])
            bucket_info_list = cls.get_bucket_obj(obs_client, bucket_name)
            for bucket_info in bucket_info_list:
                file_name = bucket_info["key"]
                file_name_list = file_name.rsplit(sep=".", maxsplit=1)
                if len(file_name_list) >= 2:
                    if file_name_list[-1] in settings.OBS_FILE_POSTFIX:
                        logger.info("collect account:{}, bucket_name:{},sensitive file:{}".format(account, bucket_name,
                                                                                                  file_name))
                        file_url = settings.OBS_FILE_URL.format(bucket_name, zone, file_name)
                        list_result.append([account, bucket_name, file_url, file_name])
                        content = cls.download_obs_data(obs_client, bucket_name, file_name)
                        if content:
                            sensitive_data = cls.get_sensitive_data(content)
                            if sensitive_data:
                                logger.info("collect account:{}, bucket_name:{},file_name:{},sensitive data:{}".format(
                                    account, bucket_name, file_name, str(sensitive_data)))
                                list_anonymous_data.append(
                                    [account, bucket_name, file_url, file_name, str(sensitive_data)])
        return list_result, list_anonymous_bucket, list_anonymous_data

    @classmethod
    def get_bucket_list(cls, obs_client, inhibition_fault=True):
        if not isinstance(obs_client, ObsClient):
            raise Exception("obs_client must be instantiated")
        list_bucket = list()
        try:
            resp = obs_client.listBuckets()
            if resp.status < 300:
                for bucket in resp.body.buckets:
                    if bucket['bucket_type'] == "OBJECT":
                        list_bucket.append(dict(bucket))
            else:
                logger.info('[get_bucket_list] errorCode:{},errorMessage:{}'.format(resp.errorCode, resp.errorMessage))
                raise Exception("Get bucket list fault")
        except Exception as e:
            logger.info("[get_bucket_list]:{},{}".format(e, traceback.format_exc()))
            if not inhibition_fault:
                raise e
        return list_bucket

    @classmethod
    def get_all_bucket(cls, ak, sk, url, inhibition_fault=True):
        location_bucket = defaultdict(list)
        with ObsClientConn(ak, sk, url) as obs_client:
            list_bucket = cls.get_bucket_list(obs_client, inhibition_fault)
            for bucket_info in list_bucket:
                location_bucket[bucket_info["location"]].append(bucket_info["name"])
            return location_bucket


class ObsClientConn(object):
    def __init__(self, ak, sk, url, timeout=180):
        self.obs_client = ObsClient(access_key_id=ak, secret_access_key=sk, server=url, timeout=timeout)

    def __enter__(self):
        return self.obs_client

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.obs_client:
            self.obs_client.close()


# noinspection DuplicatedCode
def scan_obs(query_account_list):
    """
    1.获取所有的桶信息
    2.如果这个桶是匿名用户，则遍历所有的文件和文件夹，如果是后缀名是.结尾的，则添加到列表中
    3.输出到txt中
    """
    eip_tools = EipTools()
    logger.info("############1.start to collect and output to txt######")
    result_list, list_anonymous_bucket, list_anonymous_data = list(), list(), list()
    for config_item in query_account_list:
        ak = config_item["ak"]
        sk = config_item["sk"]
        account = config_item["account"]
        location_bucket = eip_tools.get_all_bucket(ak, sk, settings.OBS_BASE_URL)
        logger.info("scan_obs:{}".format(location_bucket))
        for location, bucket_name_list in location_bucket.items():
            url = settings.OBS_URL.format(location)
            with ObsClientConn(ak, sk, url) as obs_client:
                for bucket_name in bucket_name_list:
                    ret_temp, list_anonymous_bucket_temp, list_anonymous_data_temp = eip_tools.check_bucket_info(
                        obs_client, bucket_name, account, location)
                    result_list.extend(ret_temp or [])
                    list_anonymous_bucket.extend(list_anonymous_bucket_temp or [])
                    list_anonymous_data.extend(list_anonymous_data_temp or [])
    return result_list, list_anonymous_bucket, list_anonymous_data


# noinspection DuplicatedCode
def single_scan_obs(ak, sk, account):
    eip_tools = EipTools()
    list_anonymous_file, list_anonymous_bucket, list_anonymous_data = list(), list(), list()
    single_location_bucket = eip_tools.get_all_bucket(ak, sk, settings.OBS_BASE_URL)
    logger.info("single_scan_obs:{}".format(single_location_bucket))
    for location, bucket_name_list in single_location_bucket.items():
        url = settings.OBS_URL.format(location)
        with ObsClientConn(ak, sk, url) as obs_client:
            for bucket_name in bucket_name_list:
                ret_temp, list_anonymous_bucket_temp, list_anonymous_data_temp = eip_tools.check_bucket_info(
                    obs_client, bucket_name, account, location)
                list_anonymous_file.extend(ret_temp or [])
                list_anonymous_bucket.extend(list_anonymous_bucket_temp or [])
                list_anonymous_data.extend(list_anonymous_data_temp or [])
    return list_anonymous_file, list_anonymous_bucket, list_anonymous_data
