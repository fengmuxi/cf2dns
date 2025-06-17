#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Mail: tongdongdong@outlook.com
import random
import time
import requests
from dns.qCloud import QcloudApiv3  # QcloudApiv3 DNSPod 的 API 更新了 By github@z0z0r4
from dns.aliyun import AliApi
from dns.huawei import HuaWeiApi
from log import Logger
import traceback
import configparser
import json
import subprocess
import csv
from pathlib import Path

file = 'src/config.ini'
# 创建配置文件对象
con = configparser.ConfigParser()

# 读取文件
con.read(file, encoding='utf-8')
# 获取特定section
items = con.items('DEFAULT')  # 返回结果为元组

# 可以通过dict方法转换为字典
items = dict(items)

KEY = items['key']
DOMAINS = json.loads(items['domains'])
AFFECT_NUM = int(items['affect_num'])
DNS_SERVER = int(items['dns_server'])
REGION_HW = items['region_hw']
REGION_ALI = items['region_ali']
TTL = int(items['ttl'])
TYPE = items['type']
SECRETID = items['secretid']
SECRETKEY = items['secretkey']
TIMES = int(items['times'])
CNAMES_STATUS = bool(int(items['cnames_status']))
CNAMES = json.loads(items['cnames'])

log_cf2dns = Logger('logs/cf2dns.log', level='debug')


def get_optimization_ip():
    try:
        headers = headers = {'Content-Type': 'application/json'}
        data = {"key": KEY, "type": TYPE}
        response = requests.post('https://api.hostmonit.com/get_optimization_ip', json=data, headers=headers)
        if response.status_code == 200:
            return response.json()
        else:
            log_cf2dns.logger.error("CHANGE OPTIMIZATION IP ERROR: ----Time: " + str(
                time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())) + "----MESSAGE: REQUEST STATUS CODE IS NOT 200")
            return None
    except Exception as e:
        log_cf2dns.logger.error("CHANGE OPTIMIZATION IP ERROR: ----Time: " + str(
            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())) + "----MESSAGE: " + str(e))
        return None


def changeDNS(line, s_info, c_info, domain, sub_domain, cloud, recordType):
    global AFFECT_NUM

    lines = {"CM": "移动", "CU": "联通", "CT": "电信", "AB": "境外", "DEF": "默认"}
    line = lines[line]

    try:
        create_num = AFFECT_NUM - len(s_info)
        if create_num == 0:
            for info in s_info:
                if len(c_info) == 0:
                    break
                cf_ip = c_info.pop(random.randint(0, len(c_info) - 1))["ip"]
                if cf_ip in str(s_info):
                    continue
                ret = cloud.change_record(domain, info["recordId"], sub_domain, cf_ip, recordType, line, TTL)
                if (DNS_SERVER != 1 or ret["code"] == 0):
                    log_cf2dns.logger.info("CHANGE DNS SUCCESS: ----Time: " + str(time.strftime("%Y-%m-%d %H:%M:%S",
                                                                                                time.localtime())) + "----DOMAIN: " + domain + "----SUBDOMAIN: " + sub_domain + "----RECORDLINE: " + line + "----RECORDID: " + str(
                        info["recordId"]) + "----VALUE: " + cf_ip)
                else:
                    log_cf2dns.logger.error("CHANGE DNS ERROR: ----Time: " + str(time.strftime("%Y-%m-%d %H:%M:%S",
                                                                                               time.localtime())) + "----DOMAIN: " + domain + "----SUBDOMAIN: " + sub_domain + "----RECORDLINE: " + line + "----RECORDID: " + str(
                        info["recordId"]) + "----VALUE: " + cf_ip + "----MESSAGE: " + ret["message"])
        elif create_num > 0:
            for i in range(create_num):
                if len(c_info) == 0:
                    break
                cf_ip = c_info.pop(random.randint(0, len(c_info) - 1))["ip"]
                if cf_ip in str(s_info):
                    continue
                ret = cloud.create_record(domain, sub_domain, cf_ip, recordType, line, TTL)
                if (DNS_SERVER != 1 or ret["code"] == 0):
                    log_cf2dns.logger.info("CREATE DNS SUCCESS: ----Time: " + str(time.strftime("%Y-%m-%d %H:%M:%S",
                                                                                                time.localtime())) + "----DOMAIN: " + domain + "----SUBDOMAIN: " + sub_domain + "----RECORDLINE: " + line + "----VALUE: " + cf_ip)
                else:
                    log_cf2dns.logger.error("CREATE DNS ERROR: ----Time: " + str(time.strftime("%Y-%m-%d %H:%M:%S",
                                                                                               time.localtime())) + "----DOMAIN: " + domain + "----SUBDOMAIN: " + sub_domain + "----RECORDLINE: " + line + "----VALUE: " + cf_ip + "----MESSAGE: " + ret["message"])
        else:
            for info in s_info:
                if create_num == 0 or len(c_info) == 0:
                    break
                cf_ip = c_info.pop(random.randint(0, len(c_info) - 1))["ip"]
                if cf_ip in str(s_info):
                    create_num += 1
                    continue
                ret = cloud.change_record(domain, info["recordId"], sub_domain, cf_ip, recordType, line, TTL)
                if (DNS_SERVER != 1 or ret["code"] == 0):
                    log_cf2dns.logger.info("CHANGE DNS SUCCESS: ----Time: " + str(time.strftime("%Y-%m-%d %H:%M:%S",
                                                                                                time.localtime())) + "----DOMAIN: " + domain + "----SUBDOMAIN: " + sub_domain + "----RECORDLINE: " + line + "----RECORDID: " + str(
                        info["recordId"]) + "----VALUE: " + cf_ip)
                else:
                    log_cf2dns.logger.error("CHANGE DNS ERROR: ----Time: " + str(time.strftime("%Y-%m-%d %H:%M:%S",
                                                                                               time.localtime())) + "----DOMAIN: " + domain + "----SUBDOMAIN: " + sub_domain + "----RECORDLINE: " + line + "----RECORDID: " + str(
                        info["recordId"]) + "----VALUE: " + cf_ip + "----MESSAGE: " + ret["message"])
                create_num += 1
    except Exception as e:
        log_cf2dns.logger.error("CHANGE DNS ERROR: ----Time: " + str(
            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())) + "----MESSAGE: " + str(e))


def main(cloud):
    global AFFECT_NUM, TYPE, DOMAINS
    if len(CNAMES) > 0 and CNAMES_STATUS:
        try:
            for domain, sub_domains in DOMAINS.items():
                for sub_domain, lines in sub_domains.items():
                    temp_cf_cmips = CNAMES.copy()
                    temp_cf_cuips = CNAMES.copy()
                    temp_cf_ctips = CNAMES.copy()
                    temp_cf_abips = CNAMES.copy()
                    temp_cf_defips = CNAMES.copy()
                    if DNS_SERVER == 1:
                        ret = cloud.get_record(domain, 100, sub_domain, "CNAME")
                        if ret["code"] == 0:
                            for record in ret["data"]["records"]:
                                if record["line"] == "移动" or record["line"] == "联通" or record["line"] == "电信":
                                    retMsg = cloud.del_record(domain, record["id"])
                                    if (retMsg["code"] == 0):
                                        log_cf2dns.logger.info("DELETE DNS SUCCESS: ----Time: " + str(
                                            time.strftime("%Y-%m-%d %H:%M:%S",
                                                          time.localtime())) + "----DOMAIN: " + domain + "----SUBDOMAIN: " + sub_domain + "----RECORDLINE: " +
                                                               record["line"])
                                    else:
                                        log_cf2dns.logger.error("DELETE DNS ERROR: ----Time: " + str(
                                            time.strftime("%Y-%m-%d %H:%M:%S",
                                                          time.localtime())) + "----DOMAIN: " + domain + "----SUBDOMAIN: " + sub_domain + "----RECORDLINE: " +
                                                                record["line"] + "----MESSAGE: " + retMsg["message"])
                        ret = cloud.get_record(domain, 100, sub_domain, "A")
                        if ret["code"] == 0:
                            for record in ret["data"]["records"]:
                                if record["line"] == "移动" or record["line"] == "联通" or record["line"] == "电信":
                                    retMsg = cloud.del_record(domain, record["id"])
                                    if (retMsg["code"] == 0):
                                        log_cf2dns.logger.info("DELETE DNS SUCCESS: ----Time: " + str(
                                            time.strftime("%Y-%m-%d %H:%M:%S",
                                                          time.localtime())) + "----DOMAIN: " + domain + "----SUBDOMAIN: " + sub_domain + "----RECORDLINE: " +
                                                               record["line"])
                                    else:
                                        log_cf2dns.logger.error("DELETE DNS ERROR: ----Time: " + str(
                                            time.strftime("%Y-%m-%d %H:%M:%S",
                                                          time.localtime())) + "----DOMAIN: " + domain + "----SUBDOMAIN: " + sub_domain + "----RECORDLINE: " +
                                                                record["line"] + "----MESSAGE: " + retMsg["message"])
                        ret = cloud.get_record(domain, 100, sub_domain, "AAAA")
                        if ret["code"] == 0:
                            for record in ret["data"]["records"]:
                                if record["line"] == "移动" or record["line"] == "联通" or record["line"] == "电信":
                                    retMsg = cloud.del_record(domain, record["id"])
                                    if (retMsg["code"] == 0):
                                        log_cf2dns.logger.info("DELETE DNS SUCCESS: ----Time: " + str(
                                            time.strftime("%Y-%m-%d %H:%M:%S",
                                                          time.localtime())) + "----DOMAIN: " + domain + "----SUBDOMAIN: " + sub_domain + "----RECORDLINE: " +
                                                               record["line"])
                                    else:
                                        log_cf2dns.logger.error("DELETE DNS ERROR: ----Time: " + str(
                                            time.strftime("%Y-%m-%d %H:%M:%S",
                                                          time.localtime())) + "----DOMAIN: " + domain + "----SUBDOMAIN: " + sub_domain + "----RECORDLINE: " +
                                                                record["line"] + "----MESSAGE: " + retMsg["message"])
                    ret = cloud.get_record(domain, 100, sub_domain, "A")
                    if ret["TotalCount"] > 0:
                        for record in ret["data"]["records"]:
                            if record["line"] == "移动" or record["line"] == "联通" or record["line"] == "电信":
                                retMsg = cloud.del_record(domain, record["id"])
                                if (retMsg["code"] == 0):
                                    log_cf2dns.logger.info("DELETE DNS SUCCESS: ----Time: " + str(
                                        time.strftime("%Y-%m-%d %H:%M:%S",
                                                      time.localtime())) + "----DOMAIN: " + domain + "----SUBDOMAIN: " + sub_domain + "----RECORDLINE: " +
                                                           record["line"])
                                else:
                                    log_cf2dns.logger.error("DELETE DNS ERROR: ----Time: " + str(
                                        time.strftime("%Y-%m-%d %H:%M:%S",
                                                      time.localtime())) + "----DOMAIN: " + domain + "----SUBDOMAIN: " + sub_domain + "----RECORDLINE: " +
                                                            record["line"] + "----MESSAGE: " + retMsg["message"])
                    ret = cloud.get_record(domain, 100, sub_domain, "AAAA")
                    if ret["TotalCount"] > 0:
                        for record in ret["data"]["records"]:
                            if record["line"] == "移动" or record["line"] == "联通" or record["line"] == "电信":
                                retMsg = cloud.del_record(domain, record["id"])
                                if (retMsg["code"] == 0):
                                    log_cf2dns.logger.info("DELETE DNS SUCCESS: ----Time: " + str(
                                        time.strftime("%Y-%m-%d %H:%M:%S",
                                                      time.localtime())) + "----DOMAIN: " + domain + "----SUBDOMAIN: " + sub_domain + "----RECORDLINE: " +
                                                           record["line"])
                                else:
                                    log_cf2dns.logger.error("DELETE DNS ERROR: ----Time: " + str(
                                        time.strftime("%Y-%m-%d %H:%M:%S",
                                                      time.localtime())) + "----DOMAIN: " + domain + "----SUBDOMAIN: " + sub_domain + "----RECORDLINE: " +
                                                            record["line"] + "----MESSAGE: " + retMsg["message"])
                    ret = cloud.get_record(domain, 100, sub_domain, "CNAME")
                    if DNS_SERVER != 1 or ret["code"] == 0:
                        if DNS_SERVER == 1 and "Free" in ret["data"]["domain"]["grade"] and AFFECT_NUM > 2:
                            AFFECT_NUM = 2
                        cm_info = []
                        cu_info = []
                        ct_info = []
                        ab_info = []
                        def_info = []
                        for record in ret["data"]["records"]:
                            info = {}
                            info["recordId"] = record["id"]
                            info["value"] = record["value"]
                            if record["line"] == "移动":
                                cm_info.append(info)
                            elif record["line"] == "联通":
                                cu_info.append(info)
                            elif record["line"] == "电信":
                                ct_info.append(info)
                            elif record["line"] == "境外":
                                ab_info.append(info)
                            elif record["line"] == "默认":
                                def_info.append(info)
                        for line in lines:
                            if line == "CM":
                                changeDNS("CM", cm_info, temp_cf_cmips, domain, sub_domain, cloud, "CNAME")
                            elif line == "CU":
                                changeDNS("CU", cu_info, temp_cf_cuips, domain, sub_domain, cloud, "CNAME")
                            elif line == "CT":
                                changeDNS("CT", ct_info, temp_cf_ctips, domain, sub_domain, cloud, "CNAME")
                            elif line == "AB":
                                changeDNS("AB", ab_info, temp_cf_abips, domain, sub_domain, cloud, "CNAME")
                            elif line == "DEF":
                                changeDNS("DEF", def_info, temp_cf_defips, domain, sub_domain, cloud, "CNAME")
        except Exception as e:
            traceback.print_exc()
            log_cf2dns.logger.error("CHANGE DNS ERROR: ----Time: " + str(
                time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())) + "----MESSAGE: " + str(e))
    if TYPE == 'v6':
        recordType = "AAAA"
    else:
        recordType = "A"
    if len(DOMAINS) > 0 and not CNAMES_STATUS:
        try:
            cfips = get_optimization_ip()
            if cfips == None or cfips["code"] != 200:
                log_cf2dns.logger.error("GET CLOUDFLARE IP ERROR: ----Time: " + str(
                    time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())) + "----MESSAGE: " + str(cfips["info"]))
                return
            cf_cmips = cfips["info"]["CM"]
            cf_cuips = cfips["info"]["CU"]
            cf_ctips = cfips["info"]["CT"]
            for domain, sub_domains in DOMAINS.items():
                for sub_domain, lines in sub_domains.items():
                    temp_cf_cmips = cf_cmips.copy()
                    temp_cf_cuips = cf_cuips.copy()
                    temp_cf_ctips = cf_ctips.copy()
                    temp_cf_abips = cf_ctips.copy()
                    temp_cf_defips = cf_ctips.copy()
                    if DNS_SERVER == 1:
                        ret = cloud.get_record(domain, 100, sub_domain, "CNAME")
                        if ret["code"] == 0:
                            for record in ret["data"]["records"]:
                                if record["line"] == "移动" or record["line"] == "联通" or record["line"] == "电信":
                                    retMsg = cloud.del_record(domain, record["id"])
                                    if (retMsg["code"] == 0):
                                        log_cf2dns.logger.info("DELETE DNS SUCCESS: ----Time: " + str(
                                            time.strftime("%Y-%m-%d %H:%M:%S",
                                                          time.localtime())) + "----DOMAIN: " + domain + "----SUBDOMAIN: " + sub_domain + "----RECORDLINE: " +
                                                               record["line"])
                                    else:
                                        log_cf2dns.logger.error("DELETE DNS ERROR: ----Time: " + str(
                                            time.strftime("%Y-%m-%d %H:%M:%S",
                                                          time.localtime())) + "----DOMAIN: " + domain + "----SUBDOMAIN: " + sub_domain + "----RECORDLINE: " +
                                                                record["line"] + "----MESSAGE: " + retMsg["message"])
                    ret = cloud.get_record(domain, 100, sub_domain, "CNAME")
                    if ret["TotalCount"] > 0:
                        for record in ret["data"]["records"]:
                            if record["line"] == "移动" or record["line"] == "联通" or record["line"] == "电信":
                                retMsg = cloud.del_record(domain, record["id"])
                                if (retMsg["code"] == 0):
                                    log_cf2dns.logger.info("DELETE DNS SUCCESS: ----Time: " + str(
                                        time.strftime("%Y-%m-%d %H:%M:%S",
                                                      time.localtime())) + "----DOMAIN: " + domain + "----SUBDOMAIN: " + sub_domain + "----RECORDLINE: " +
                                                           record["line"])
                                else:
                                    log_cf2dns.logger.error("DELETE DNS ERROR: ----Time: " + str(
                                        time.strftime("%Y-%m-%d %H:%M:%S",
                                                      time.localtime())) + "----DOMAIN: " + domain + "----SUBDOMAIN: " + sub_domain + "----RECORDLINE: " +
                                                            record["line"] + "----MESSAGE: " + retMsg["message"])
                    ret = cloud.get_record(domain, 100, sub_domain, recordType)
                    if DNS_SERVER != 1 or ret["code"] == 0:
                        if DNS_SERVER == 1 and "Free" in ret["data"]["domain"]["grade"] and AFFECT_NUM > 2:
                            AFFECT_NUM = 2
                        cm_info = []
                        cu_info = []
                        ct_info = []
                        ab_info = []
                        def_info = []
                        for record in ret["data"]["records"]:
                            info = {}
                            info["recordId"] = record["id"]
                            info["value"] = record["value"]
                            if record["line"] == "移动":
                                cm_info.append(info)
                            elif record["line"] == "联通":
                                cu_info.append(info)
                            elif record["line"] == "电信":
                                ct_info.append(info)
                            elif record["line"] == "境外":
                                ab_info.append(info)
                            elif record["line"] == "默认":
                                def_info.append(info)
                        for line in lines:
                            if line == "CM":
                                changeDNS("CM", cm_info, temp_cf_cmips, domain, sub_domain, cloud, recordType)
                            elif line == "CU":
                                changeDNS("CU", cu_info, temp_cf_cuips, domain, sub_domain, cloud, recordType)
                            elif line == "CT":
                                changeDNS("CT", ct_info, temp_cf_ctips, domain, sub_domain, cloud, recordType)
                            elif line == "AB":
                                changeDNS("AB", ab_info, temp_cf_abips, domain, sub_domain, cloud, recordType)
                            elif line == "DEF":
                                changeDNS("DEF", def_info, temp_cf_defips, domain, sub_domain, cloud, recordType)
        except Exception as e:
            traceback.print_exc()
            log_cf2dns.logger.error("CHANGE DNS ERROR: ----Time: " + str(
                time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())) + "----MESSAGE: " + str(e))


def main_file(cloud):
    global AFFECT_NUM, TYPE, DOMAINS
    recordType = "A"
    if len(DOMAINS) > 0 and not CNAMES_STATUS:
        try:
            # 假设要执行的可执行文件是 /usr/bin/firefox
            process = subprocess.Popen(['./CloudflareST/CloudflareST', '-f', './CloudflareST/ip.txt', '-o',
                                        './CloudflareST/result.csv', '-sl', '1'])
            # 可以在这里做其他操作，比如等待进程结束
            return_code = process.wait()
            log_cf2dns.logger.info("测试ip速度结束返回信息: ----Time: " + str(
                time.strftime("%Y-%m-%d %H:%M:%S",
                              time.localtime())) + "----code: " + str(return_code))
            with open('./CloudflareST/result.csv', 'r', encoding='utf-8') as ip_file:
                # 创建 CSV 读取器
                file_content = csv.reader(ip_file)
                next(file_content)  # 跳过标题行

                # 跳过标题行
                cfips = []
                ip_file_raws = []
                for parts in file_content:
                    raw_txt = ''
                    # 第一个部分就是 IP 地址
                    ip = parts[0]
                    raw_txt += f'{ip}:2082#美国{parts[len(parts)-1]}'
                    log_cf2dns.logger.info("测试ip速度结束返回信息ip: ----Time: " + str(
                        time.strftime("%Y-%m-%d %H:%M:%S",
                                      time.localtime())) + "----ip: " + ip)
                    if len(cfips) < 10:
                        cfips.append({'ip': ip})
                        ip_file_raws.append(raw_txt)
                    else:
                        break
            try:
                # 创建父目录（如果需要）
                Path('./CloudflareST/resultIp.txt').parent.mkdir(parents=True, exist_ok=True)

                # 写入文件
                with open("./CloudflareST/resultIp.txt", "w", encoding="utf-8") as f:
                    for line in ip_file_raws:
                        f.write(line + "\n")

            except PermissionError as e:
                raise e
            except FileNotFoundError as e:
                raise e
            except Exception as e:
                raise e
            for domain, sub_domains in DOMAINS.items():
                for sub_domain, lines in sub_domains.items():
                    temp_cf_defips = cfips.copy()
                    if DNS_SERVER == 1:
                        ret = cloud.get_record(domain, 100, sub_domain, "CNAME")
                        if ret["code"] == 0:
                            for record in ret["data"]["records"]:
                                if record["line"] == "移动" or record["line"] == "联通" or record["line"] == "电信":
                                    retMsg = cloud.del_record(domain, record["id"])
                                    if (retMsg["code"] == 0):
                                        log_cf2dns.logger.info("DELETE DNS SUCCESS: ----Time: " + str(
                                            time.strftime("%Y-%m-%d %H:%M:%S",
                                                          time.localtime())) + "----DOMAIN: " + domain + "----SUBDOMAIN: " + sub_domain + "----RECORDLINE: " +
                                                               record["line"])
                                    else:
                                        log_cf2dns.logger.error("DELETE DNS ERROR: ----Time: " + str(
                                            time.strftime("%Y-%m-%d %H:%M:%S",
                                                          time.localtime())) + "----DOMAIN: " + domain + "----SUBDOMAIN: " + sub_domain + "----RECORDLINE: " +
                                                                record["line"] + "----MESSAGE: " + retMsg["message"])
                    ret = cloud.get_record(domain, 100, sub_domain, "CNAME")
                    if ret["TotalCount"] > 0:
                        for record in ret["data"]["records"]:
                            if record["line"] == "移动" or record["line"] == "联通" or record["line"] == "电信":
                                retMsg = cloud.del_record(domain, record["id"])
                                if (retMsg["code"] == 0):
                                    log_cf2dns.logger.info("DELETE DNS SUCCESS: ----Time: " + str(
                                        time.strftime("%Y-%m-%d %H:%M:%S",
                                                      time.localtime())) + "----DOMAIN: " + domain + "----SUBDOMAIN: " + sub_domain + "----RECORDLINE: " +
                                                           record["line"])
                                else:
                                    log_cf2dns.logger.error("DELETE DNS ERROR: ----Time: " + str(
                                        time.strftime("%Y-%m-%d %H:%M:%S",
                                                      time.localtime())) + "----DOMAIN: " + domain + "----SUBDOMAIN: " + sub_domain + "----RECORDLINE: " +
                                                            record["line"] + "----MESSAGE: " + retMsg["message"])
                    ret = cloud.get_record(domain, 100, sub_domain, recordType)
                    if DNS_SERVER != 1 or ret["code"] == 0:
                        if DNS_SERVER == 1 and "Free" in ret["data"]["domain"]["grade"] and AFFECT_NUM > 2:
                            AFFECT_NUM = 2
                        cm_info = []
                        cu_info = []
                        ct_info = []
                        ab_info = []
                        def_info = []
                        for record in ret["data"]["records"]:
                            info = {}
                            info["recordId"] = record["id"]
                            info["value"] = record["value"]
                            if record["line"] == "移动":
                                cm_info.append(info)
                            elif record["line"] == "联通":
                                cu_info.append(info)
                            elif record["line"] == "电信":
                                ct_info.append(info)
                            elif record["line"] == "境外":
                                ab_info.append(info)
                            elif record["line"] == "默认":
                                def_info.append(info)
                        for line in lines:
                            if line == "CM":
                                changeDNS("CM", cm_info, temp_cf_defips, domain, sub_domain, cloud, recordType)
                            elif line == "CU":
                                changeDNS("CU", cu_info, temp_cf_defips, domain, sub_domain, cloud, recordType)
                            elif line == "CT":
                                changeDNS("CT", ct_info, temp_cf_defips, domain, sub_domain, cloud, recordType)
                            elif line == "AB":
                                changeDNS("AB", ab_info, temp_cf_defips, domain, sub_domain, cloud, recordType)
                            elif line == "DEF":
                                changeDNS("DEF", def_info, temp_cf_defips, domain, sub_domain, cloud, recordType)


        except Exception as e:
            traceback.print_exc()
            log_cf2dns.logger.error("CHANGE DNS ERROR: ----Time: " + str(
                time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())) + "----MESSAGE: " + str(e))


if __name__ == '__main__':
    cloud = None
    if DNS_SERVER == 1:
        cloud = QcloudApiv3(SECRETID, SECRETKEY)
    elif DNS_SERVER == 2:
        cloud = AliApi(SECRETID, SECRETKEY, REGION_ALI)
    elif DNS_SERVER == 3:
        cloud = HuaWeiApi(SECRETID, SECRETKEY, REGION_HW)
    while True:
        main(cloud)
        main_file(cloud)
        log_cf2dns.logger.info("CHANGE DNS SUCCESS: ----Time: " + str(
            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())) + "----MESSAGE: ALL DONE")
        time.sleep(TIMES)
