from pymysql.converters import escape_string
from lib.utils.outputer import generate_html
from lib.utils.timecalc import get_time
from lib.utils.DBUtil import DBUtil
from lib.rules.rules_sqli import Get_sql_errors
from lib.rules.enums import VulType
from lib.utils.CommonLog import CommonLog
import copy

class SQLError(object):
    def __init__(self, wapper):
        self.wapper = wapper
        self.db = DBUtil()
        self.logger = CommonLog(__name__).getlog()
        self.vulType = VulType.SQLI_ERROR_BASE
        self.template_name = 'template_sql_error.html'
        self.sql_error = Get_sql_errors()
        self.error_sql_list = ['\'','"','%df\'']
        self.error_sql_list_length = len(self.error_sql_list)
        self.sql_index = []
        self.request_count = 0

    @get_time
    def scan(self,request_data):
        #first_request_data, first_req_raw = self.wapper.generate_request_for_first(request_data)
        #self.wapper.processRequest(first_request_data)
        self.logger.info('[*] SQL报错注入探测插件启动')
        flag = False
        for error_sql_str in self.error_sql_list:
            request_data_copy = copy.deepcopy(request_data)
            gen_list = self.wapper.generate_request_data_list(request_data_copy, error_sql_str, 1)
            for index, val in enumerate(gen_list):
                if index not in self.sql_index: # 判断是否是存在的index 下标，不是才探测。保证同一个参数如果有探测到sql之后，后面就不探测这个参数
                    resp = self.wapper.processRequest(val)
                    resp_raw = self.wapper.generateResponse(resp)
                    self.request_count += 1
                    for sql_regex, dbms_type in self.sql_error:
                        match = sql_regex.search(resp_raw)
                        if match:
                            flag = True
                            self.sql_index.append(index)  # 如果该请求包判断存在注入，就加入list，下次不探测这个index
                            self.logger.critical('[+] 发现SQL报错注入, {}'.format(match.group()))
                            self.db.save("insert into sql_error(`request_data`, `response`, `host`, `dbms`) values ('{}', '{}', '{}', '{}')".format(escape_string(self.wapper.generateRequest(val)), escape_string(resp_raw), val['host'], dbms_type))
                            break

        if flag:
            self.fetch_sql()
        self.logger.info('[*] SQL注入探测完成, 共发送 {} 个请求'.format(self.request_count))


    def fetch_sql(self):
        sql = 'select `create_time`, `host`, `dbms`, `request_data`, `response` from sql_error where to_days(create_time)=to_days(now())'
        items = self.db.get_all(sql)
        self.logger.info('[+] #####正在生成SQL报错注入漏洞报告#####')
        generate_html(items, self.template_name, self.vulType)
        self.logger.info('[+] #####SQL报错注入漏洞报告生成完成#####')







