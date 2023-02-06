import uuid
from conf.ConfigFileModifyHandler import Config
import copy
import json
from lib.utils.DBUtil import DBUtil
import requests
from lib.utils.CommonLog import CommonLog
from pymysql.converters import escape_string
from lib.utils.outputer import generate_html
from lib.utils.timecalc import get_time
from lib.rules.enums import VulType


class RCE(object):
    def __init__(self, wapper):
        self.wapper = wapper
        self.rce_str = 'rrr'
        self.db = DBUtil()
        self.dnslog_key = Config.get_instance().get("app.SSRF_API_KEY")
        self.logger = CommonLog(__name__).getlog()
        self.template_name = 'template_ssrf.html'
        self.vulType = VulType.CMD_INNJECTION

    # def generate_request_data_list(self, request_data):
    #     type = request_data['content_type']
    #     param_url_dict = request_data['param_in_url']
    #     param_body_dict = request_data['param_in_body']
    #     # json_body_dict = request_data['body']
    #     request_data_list = []
    #     copy_data = copy.deepcopy(request_data)
    #     if type == 4:
    #         for i in self.wapper.updateJsonObjectFromStr(param_url_dict, self.ssrf_str, 2):
    #             request_data['param_in_url'] = i
    #             try:
    #                 request_data['body'] = json.loads(request_data['body'])
    #             except:
    #                 pass
    #             request_data_list.append(copy.deepcopy(request_data))
    #
    #         for j in self.wapper.updateJsonObjectFromStr(json.loads(copy_data['body']), self.ssrf_str,
    #                                                      2):
    #             copy_data['body'] = j
    #             request_data_list.append(copy.deepcopy(copy_data))
    #         return request_data_list
    #     else:
    #         for i in self.wapper.updateJsonObjectFromStr(param_url_dict, self.ssrf_str, 2):
    #             request_data['param_in_url'] = i
    #             # print(request_data)
    #             request_data_list.append(copy.deepcopy(request_data))
    #
    #         for j in self.wapper.updateJsonObjectFromStr(param_body_dict, self.ssrf_str, 2):
    #             copy_data['param_in_body'] = j
    #             request_data_list.append(copy.deepcopy(copy_data))
    #         return request_data_list

    @get_time
    def scan(self, request_data):
        self.logger.info('[*] RCE探测插件启动')
        #gen_list = self.generate_request_data_list(request_data)
        gen_list = self.wapper.generate_request_data_list(request_data, self.rce_str, 3)
        #print(gen_list)
        # for i in gen_list:
        #     self.wapper.processRequest(i)
        #print(self.wapper.rce_list)
        for i, val in enumerate(gen_list):
            #print(f"---{i}---")
            resp = self.wapper.processRequest(val)
            resp_raw = self.wapper.generateResponse(resp)
            req_raw = self.wapper.generateRequest(val)
            #print(self.wapper.rce_list[i])
            sql = f"insert into ssrf(`payload`,`request_data`,`response`,`host`,`vuType`) VALUES ('{self.wapper.rce_list[i]}', '{escape_string(req_raw)}', '{escape_string(resp_raw)}' ,'{val['host']}', 2)"
            #print(sql)
            self.db.save(sql)

        #time.sleep(30)
        self.fetch_dnslog(self.wapper.rce_list)
        self.logger.info('[*] RCE 探测完成, 共发送 {} 个请求'.format(len(gen_list)))

    def fetch_dnslog(self, rce_list):
        url_web = f'http://dnslog.cn/api/{self.dnslog_key}/*.{self.rce_str}.dnslog.cn/web/'
        url_dns = f'http://dnslog.cn/api/{self.dnslog_key}/*.{self.rce_str}.dnslog.cn/dns/'
        res_web = requests.get(url_web, timeout=60).text
        res_dns = requests.get(url_dns, timeout=60).text
        flag = False
        for val in rce_list:
            if val in res_web or val in res_dns:
                self.logger.critical(f'[+] success,fetch vul,{val} has dnslog record')
                sql = f"update ssrf set is_vul = 1 where payload='{val}' and vuType=2"
                self.db.update(sql)
                flag = True
        if flag:
            items = self.db.get_all(
                "select create_time, host, payload, request_data, response from ssrf where to_days(create_time)=to_days(now()) and is_vul=1 and vuType=2")
            self.logger.info('[+] #####正在生成RCE漏洞报告#####')
            generate_html(items, self.template_name, self.vulType)
            self.logger.info('[+] #####RCE漏洞报告生成完成#####')
