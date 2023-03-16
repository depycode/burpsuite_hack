from pymysql.converters import escape_string
from lib.utils.timecalc import get_time
import copy
from lib.utils.CommonLog import CommonLog
from lib.utils.DBUtil import DBUtil
import re
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.preprocessing import StandardScaler
from scipy import spatial
from lib.utils.outputer import generate_html
from lib.rules.enums import VulType
from conf.ConfigFileModifyHandler import Config

class SQLBool(object):
    def __init__(self, wapper, model, content_type):
        self.wapper = wapper
        self.model = model
        self.content_type = content_type
        self.logger = CommonLog(__name__).getlog()
        self.db = DBUtil()
        self.vulType = VulType.SQLI_BOOL_BASE
        self.template_name = 'template_sql_bool.html'
        self.similar = float(Config.get_instance().get("score.SIMILAR"))
        self.cosin_score = int(Config.get_instance().get("score.COSINSCORE"))
        self.risk = [0, 1]  # 0 疑似，1 确定
        self.reportFlag = False
        #20220727 优化，当原始包有数据 单引号异常，双引号返回数据为空的情况
        self.bool_str_tuple = ('\'', '\'\'','\' \'')
        self.bool_str_tuple_second = ("'||x||'", "'||'")
        self.bool_str_tuple_third = ("'+x+'", "'+'") if self.content_type == 4 else ("'%2bx%2b'", "'%2b'")
        #20220809 优化int类型注入误报，将-0 改为 -0-0
        self.bool_int_tuple = ('-ab', '-0-0-0', '-false')
        #20221024 将1-x 变为 (1-x)
        self.bool_order_tuple = (",(1-xaxfe)", ",(1)",",true")
        #20221218 双引号
        self.bool_double_quotes_tuple = ('"','""','" "')
        self.bool_double_quotes_tuple_second = ('"||x||"', '"||"')

        self.replace_status = Config.get_instance().get("app.REPLACE_STATUS")
        self.replace_regex = re.compile(Config.get_instance().get("REPLACE.REGEX"))
        self.remove_payload = self.bool_str_tuple + self.bool_str_tuple_second + self.bool_str_tuple_third + self.bool_int_tuple + self.bool_order_tuple + self.bool_double_quotes_tuple + self.bool_double_quotes_tuple_second

        ### 带有随机值干扰
        self.bool_rdm = [('\'','\' \'',"'||'"),('-ab','-0-0-0','-false'),(',(1-xaxfe)',',(1)',',true')]

      
    def removeRandomContent(self, page):
        remove_content = re.sub(self.replace_regex, '',page)
        # 替换返回包中的payload为空，降低干扰
        for p in self.remove_payload:
            remove_content = remove_content.replace(p,'')
        return remove_content

    def get_score(self, raw1, raw2):
        """
        获取相似度
        :param raw1:
        :param raw2:
        :return:
        """
        # e1 = self.model.encode(raw_1)
        # e2 = self.model.encode(raw_2)
        # return float(cos_sim(e1, e2))
        return self.model.get_score(raw1,raw2)

    def no_header(self, raw):
        """
        去掉header 头，保存response body
        :param raw:
        :return:
        """
        r = raw.split('\r\n\r\n', 1)[1]
        if r:
            if self.replace_status =='YES':
                x =  self.removeRandomContent(r)
                return x
            return r
        return "empty response"

    def calculation(self,html):
        list_num = []
        list_signal = []
        # 步骤一
        cv = CountVectorizer()
        data = cv.fit_transform(html)
        std = StandardScaler()
        data_list = std.fit_transform(data.toarray())
        # 步骤二
        for line in data_list:
            list_num.append(round(spatial.distance.cosine(data_list[0], line), 2))
        num = 0
        # 步骤三
        for signal in list_num:
            if signal != 0:
                if 1 / signal * 100 < self.cosin_score:
                    list_signal.append(num)
            num = num + 1
        return list_signal


    def payload_str(self, t, s1, s2):
        return str(t) + '<br>' + str(s1) + ' === ' + str(s2)

    def payload_rdm(self,p):
        """
        带有随机值的
        :param p:
        :return:
        """
        return 'random' + '<br>' + str(p)

    def no_header_list(self,resp_list):
        return list(map(self.no_header,resp_list))
    
    #降低部分误报
    def func_equal(self,*args):
        # 所有值都相等返回False
        if len(set(args))==1:
            return False
        # 否则返回True
        return True

    @get_time
    def scan(self, request_data):
        self.logger.info('[*] SQL BOOL 注入探测插件启动')
        req_raw_first, resp_raw_first = self.wapper.generate_request_for_first(request_data)
        resp_raw_first_no_header = self.no_header(resp_raw_first)
        false_request_list = self.wapper.generate_request_data_list(copy.deepcopy(request_data), self.bool_str_tuple[0],
                                                                    1)
        true_request_list = self.wapper.generate_request_data_list(copy.deepcopy(request_data), self.bool_str_tuple[1],
                                                                   1)
        true_request_list_1 = self.wapper.generate_request_data_list(copy.deepcopy(request_data), self.bool_str_tuple[2],
                                                                   1)
        false_request_list_2 = self.wapper.generate_request_data_list(copy.deepcopy(request_data),
                                                                      self.bool_str_tuple_second[0], 1)
        true_request_list_2 = self.wapper.generate_request_data_list(copy.deepcopy(request_data),
                                                                     self.bool_str_tuple_second[1], 1)
        false_request_list_3 = self.wapper.generate_request_data_list(copy.deepcopy(request_data),
                                                                      self.bool_str_tuple_third[0], 1)
        true_request_list_3 = self.wapper.generate_request_data_list(copy.deepcopy(request_data),
                                                                     self.bool_str_tuple_third[1], 1)
        falst_request_intlist4 = self.wapper.generate_request_data_list(copy.deepcopy(request_data),
                                                                        self.bool_int_tuple[0], 1)
        true_request_intlist4 = self.wapper.generate_request_data_list(copy.deepcopy(request_data),
                                                                       self.bool_int_tuple[1], 1)
        true_request_intlist_4_1 = self.wapper.generate_request_data_list(copy.deepcopy(request_data),
                                                                          self.bool_int_tuple[2], 1)
        false_request_orderlist5 = self.wapper.generate_request_data_list(copy.deepcopy(request_data),
                                                                          self.bool_order_tuple[0], 1)
        true_request_orderlist5 = self.wapper.generate_request_data_list(copy.deepcopy(request_data),
                                                                         self.bool_order_tuple[1], 1)
        true_request_orderlist5_1 = self.wapper.generate_request_data_list(copy.deepcopy(request_data),
                                                                         self.bool_order_tuple[2], 1)

        false_request_double_quotes_list = self.wapper.generate_request_data_list(copy.deepcopy(request_data), self.bool_double_quotes_tuple[0],
                                                                    1)
        true_request_double_quotes_list = self.wapper.generate_request_data_list(copy.deepcopy(request_data), self.bool_double_quotes_tuple[1],
                                                                   1)
        true_request_double_quotes_list_1 = self.wapper.generate_request_data_list(copy.deepcopy(request_data), self.bool_double_quotes_tuple[2],
                                                                   1)
        false_request_double_quotes_list_2 = self.wapper.generate_request_data_list(copy.deepcopy(request_data),
                                                                      self.bool_double_quotes_tuple_second[0], 1)
        true_request_double_quotes_list_2 = self.wapper.generate_request_data_list(copy.deepcopy(request_data),
                                                                      self.bool_double_quotes_tuple_second[1], 1)


        for false_request, true_request, true_request_1 ,false_request_2, true_request_2, false_request_3, true_request_3, false_request_4, true_request_4, true_request_4_1, false_request_5, true_request_5, true_request_5_1,false_request_double_quotes,true_request_double_quotes, true_request_double_quotes_1,false_request_double_quotes_2,true_request_double_quotes_2 in zip(
                false_request_list, true_request_list,true_request_list_1,
                false_request_list_2,
                true_request_list_2, false_request_list_3, true_request_list_3, falst_request_intlist4,
                true_request_intlist4, true_request_intlist_4_1, false_request_orderlist5, true_request_orderlist5,true_request_orderlist5_1,false_request_double_quotes_list,true_request_double_quotes_list,true_request_double_quotes_list_1,false_request_double_quotes_list_2,true_request_double_quotes_list_2):
            strFlag = False
            intFlag = False
            orderFlag = False
            strdouble_quotesFlag = False

            false_response = self.wapper.generateResponse(self.wapper.processRequest(false_request))
            true_response = self.wapper.generateResponse(self.wapper.processRequest(true_request))
            true_response_1 = self.wapper.generateResponse(self.wapper.processRequest(true_request_1))
            false_score = self.get_score(self.no_header(false_response), resp_raw_first_no_header)
            true_score = self.get_score(self.no_header(true_response), resp_raw_first_no_header)
            true_score_1 = self.get_score(self.no_header(true_response_1), resp_raw_first_no_header)
            true_score_1_2 = self.get_score(self.no_header(true_response),self.no_header(true_response_1)) # 比较'' 和 ' '
            false_score_1_2 = self.get_score(self.no_header(true_response),self.no_header(false_response)) # 比较' 和 ''
            verify_equal = self.func_equal(self.no_header(true_response),self.no_header(true_response_1),self.no_header(false_response))
            # 进行第一步判断 ', ''
            if (false_score <= self.similar and true_score > self.similar) or (false_score <= self.similar and true_score_1 > self.similar) or (false_score <= self.similar and true_score_1_2 >self.similar and false_score_1_2<=self.similar and verify_equal):
                self.reportFlag = True
                strFlag = True
                # 进行第二次判断确认
                false_response_2 = self.wapper.generateResponse(self.wapper.processRequest(false_request_2))
                true_response_2 = self.wapper.generateResponse(self.wapper.processRequest(true_request_2))
                false_score_2 = self.get_score(self.no_header(false_response_2), resp_raw_first_no_header)
                true_score_2 = self.get_score(self.no_header(true_response_2), resp_raw_first_no_header)
                if false_score_2 <= self.similar and true_score_2 > self.similar:
                    self.logger.critical(
                        '[+] 确认存在Bool(str)型SQL注入，false_score={}, true_score={}'.format(false_score_2, true_score_2))
                    self.db.save(
                        "insert into sql_bool (`host`,`first_req`,`first_resp`,`bool_true_req`,`bool_true_resp`, `bool_false_req`, `bool_false_resp`, `payload`, risk) VALUES ('{}','{}','{}','{}','{}','{}','{}','{}',{})".format(
                            request_data['host'], escape_string(req_raw_first), escape_string(resp_raw_first),
                            escape_string(self.wapper.generateRequest(true_request_2)), escape_string(true_response_2),
                            escape_string(self.wapper.generateRequest(false_request_2)),
                            escape_string(false_response_2),
                            escape_string(self.payload_str(self.bool_str_tuple_second, false_score_2, true_score_2)),1))
                else:
                    false_response_3 = self.wapper.generateResponse(self.wapper.processRequest(false_request_3))
                    true_response_3 = self.wapper.generateResponse(self.wapper.processRequest(true_request_3))
                    false_score_3 = self.get_score(self.no_header(false_response_3), resp_raw_first_no_header)
                    true_score_3 = self.get_score(self.no_header(true_response_3), resp_raw_first_no_header)
                    if false_score_3 <= self.similar and true_score_3 > self.similar:
                        self.reportFlag = True
                        self.logger.critical(
                            '[+] 确认存在Bool(str)型SQL注入，false_score={}, true_score={}'.format(false_score_3, true_score_3))
                        self.db.save(
                            "insert into sql_bool (`host`,`first_req`,`first_resp`,`bool_true_req`,`bool_true_resp`, `bool_false_req`, `bool_false_resp`, `payload`, risk) VALUES ('{}','{}','{}','{}','{}','{}','{}','{}',{})".format(
                                request_data['host'], escape_string(req_raw_first), escape_string(resp_raw_first),
                                escape_string(self.wapper.generateRequest(true_request_3)),
                                escape_string(true_response_3),
                                escape_string(self.wapper.generateRequest(false_request_3)),
                                escape_string(false_response_3),
                                escape_string(self.payload_str(self.bool_str_tuple_third, false_score_3, true_score_3)),1))
                    else:
                        self.reportFlag = True
                        self.logger.critical(
                            '[+] 疑似存在Bool(str)型SQL注入，false_score={}, true_score={}, true_score_1={}, true_score_1_2={}'.format(false_score, true_score,true_score_1,true_score_1_2))
                        self.db.save(
                            "insert into sql_bool (`host`,`first_req`,`first_resp`,`bool_true_req`,`bool_true_resp`, `bool_false_req`, `bool_false_resp`, `payload`, risk) VALUES ('{}','{}','{}','{}','{}','{}','{}','{}',{})".format(
                                request_data['host'], escape_string(req_raw_first), escape_string(resp_raw_first),
                                escape_string(self.wapper.generateRequest(true_request)), escape_string(true_response),
                                escape_string(self.wapper.generateRequest(false_request)),
                                escape_string(false_response),
                                escape_string(self.payload_str(self.bool_str_tuple, false_score, true_score)+" === " +str(true_score_1) +" === " +str(true_score_1_2)),0))

            else:
                false_response_4 = self.wapper.generateResponse(self.wapper.processRequest(false_request_4))
                true_response_4 = self.wapper.generateResponse(self.wapper.processRequest(true_request_4))
                false_score_4 = self.get_score(self.no_header(false_response_4), resp_raw_first_no_header)
                true_score_4 = self.get_score(self.no_header(true_response_4), resp_raw_first_no_header)
                # 20230112 优化 int 的漏报
                true_response_4_1 = self.wapper.generateResponse(self.wapper.processRequest(true_request_4_1))
                true_score_4_1 = self.get_score(self.no_header(true_response_4_1), resp_raw_first_no_header)
                true_ture_score = self.get_score(self.no_header(true_response_4_1), self.no_header(true_response_4))
                true_false_score = self.get_score(self.no_header(true_response_4_1),self.no_header(false_response_4))
                #self.logger.info(
                #            'test，false_score={}, true_score={}'.format(false_score_4, true_ture_score))
                #print(str(false_score_4)+'---'+str(true_score_4))
                if (false_score_4 <= self.similar and true_score_4 > self.similar) or (false_score_4 <= self.similar and true_ture_score>self.similar and true_false_score<self.similar):
                    self.reportFlag = True
                    intFlag = True
                    # 进行第二次判断确认
                    #true_response_4_1 = self.wapper.generateResponse(self.wapper.processRequest(true_request_4_1))
                    #true_score_4_1 = self.get_score(self.no_header(true_response_4_1), resp_raw_first_no_header)
                    if true_score_4_1 > self.similar:
                        self.logger.critical(
                            '[+] 确定存在Bool(int)型SQL注入，false_score={}, true_score={}'.format(false_score_4, true_score_4))
                        self.db.save(
                            "insert into sql_bool (`host`,`first_req`,`first_resp`,`bool_true_req`,`bool_true_resp`, `bool_false_req`, `bool_false_resp`, `payload`, risk) VALUES ('{}','{}','{}','{}','{}','{}','{}','{}',{})".format(
                                request_data['host'], escape_string(req_raw_first), escape_string(resp_raw_first),
                                escape_string(self.wapper.generateRequest(true_request_4_1)),
                                escape_string(true_response_4_1),
                                escape_string(self.wapper.generateRequest(false_request_4)),
                                escape_string(false_response_4),
                                escape_string(self.payload_str(self.bool_int_tuple, false_score_4, true_score_4_1)),1))
                    else:
                        self.logger.critical(
                            '[+] 疑似存在Bool(int)型SQL注入，false_score={}, true_score={}, true_true_score={}'.format(false_score_4, true_score_4,true_ture_score))
                        self.db.save(
                            "insert into sql_bool (`host`,`first_req`,`first_resp`,`bool_true_req`,`bool_true_resp`, `bool_false_req`, `bool_false_resp`, `payload`, risk) VALUES ('{}','{}','{}','{}','{}','{}','{}','{}',{})".format(
                                request_data['host'], escape_string(req_raw_first), escape_string(resp_raw_first),
                                escape_string(self.wapper.generateRequest(true_request_4)),
                                escape_string(true_response_4),
                                escape_string(self.wapper.generateRequest(false_request_4)),
                                escape_string(false_response_4),
                                escape_string(
                                    self.payload_str(self.bool_int_tuple, false_score_4, true_score_4) + " === " + str(true_ture_score) + " -> " + str(self.bool_int_tuple[1]) +":::" + str(self.bool_int_tuple[2]) 
                                    ),0))

            #if strFlag == False and intFlag == False:
            if len(set({strFlag, intFlag})) == 1:
                false_response_5 = self.wapper.generateResponse(self.wapper.processRequest(false_request_5))
                true_response_5 = self.wapper.generateResponse(self.wapper.processRequest(true_request_5))
                false_score_5 = self.get_score(self.no_header(false_response_5), resp_raw_first_no_header)
                true_score_5 = self.get_score(self.no_header(true_response_5), resp_raw_first_no_header)
                if false_score_5 <= self.similar and true_score_5 > self.similar:
                    self.reportFlag = True
                    orderFlag = True
                    # 进行第二次判断确认
                    true_response_5_1 = self.wapper.generateResponse(self.wapper.processRequest(true_request_5_1))
                    true_score_5_1 = self.get_score(self.no_header(true_response_5_1), resp_raw_first_no_header)
                    if true_score_5_1 > self.similar:
                        self.logger.critical(
                            '[+] 确定存在Bool(order)型SQL注入，false_score={}, true_score={}'.format(false_score_5, true_score_5))
                        self.db.save(
                            "insert into sql_bool (`host`,`first_req`,`first_resp`,`bool_true_req`,`bool_true_resp`, `bool_false_req`, `bool_false_resp`, `payload`, risk) VALUES ('{}','{}','{}','{}','{}','{}','{}','{}',{})".format(
                                request_data['host'], escape_string(req_raw_first), escape_string(resp_raw_first),
                                escape_string(self.wapper.generateRequest(true_request_5_1)),
                                escape_string(true_response_5_1),
                                escape_string(self.wapper.generateRequest(false_request_5)),
                                escape_string(false_response_5),
                                escape_string(self.payload_str(self.bool_order_tuple, false_score_5, true_score_5_1)),1))

                    else:
                        self.logger.critical(
                            '[+] 疑似存在Bool(order)型SQL注入，false_score={}, true_score={}'.format(false_score_5, true_score_5))
                        self.db.save(
                            "insert into sql_bool (`host`,`first_req`,`first_resp`,`bool_true_req`,`bool_true_resp`, `bool_false_req`, `bool_false_resp`, `payload`, risk) VALUES ('{}','{}','{}','{}','{}','{}','{}','{}',{})".format(
                                request_data['host'], escape_string(req_raw_first), escape_string(resp_raw_first),
                                escape_string(self.wapper.generateRequest(true_request_5)),
                                escape_string(true_response_5),
                                escape_string(self.wapper.generateRequest(false_request_5)),
                                escape_string(false_response_5),
                                escape_string(
                                    self.payload_str(self.bool_order_tuple, false_score_5, true_score_5)),0))

            if len(set({strFlag, intFlag, orderFlag})) == 1:
                false_response_double_quotes = self.wapper.generateResponse(self.wapper.processRequest(false_request_double_quotes))
                true_response_double_quotes = self.wapper.generateResponse(self.wapper.processRequest(true_request_double_quotes))
                true_response_double_quotes_1 = self.wapper.generateResponse(self.wapper.processRequest(true_request_double_quotes_1))
                false_score_double_quotes = self.get_score(self.no_header(false_response_double_quotes), resp_raw_first_no_header)
                true_score_double_quotes = self.get_score(self.no_header(true_response_double_quotes), resp_raw_first_no_header)
                true_score_double_quotes_1 = self.get_score(self.no_header(true_response_double_quotes_1), resp_raw_first_no_header)
                true_score_double_quotes_1_2 = self.get_score(self.no_header(true_response_double_quotes),
                                                self.no_header(true_response_double_quotes_1))  # 比较"" 和 " "
                false_score_double_quotes_1_2 = self.get_score(self.no_header(true_response_double_quotes),
                                                 self.no_header(false_response_double_quotes))  # 比较" 和 ""
                
                verify_double_equal = self.func_equal(self.no_header(true_response_double_quotes),self.no_header(true_response_double_quotes_1),self.no_header(false_response_double_quotes))
                if (false_score_double_quotes <= self.similar and true_score_double_quotes > self.similar) or (
                        false_score_double_quotes <= self.similar and true_score_double_quotes_1 > self.similar) or (
                        false_score_double_quotes <= self.similar and true_score_double_quotes_1_2 > self.similar and false_score_double_quotes_1_2 <= self.similar and verify_double_equal):
                    self.reportFlag = True
                    strdouble_quotesFlag = True
                    # 进行第二次判断确认
                    false_response_double_quotes_2 = self.wapper.generateResponse(self.wapper.processRequest(false_request_double_quotes_2))
                    true_response_double_quotes_2 = self.wapper.generateResponse(self.wapper.processRequest(true_request_double_quotes_2))
                    false_score_double_quotes_2 = self.get_score(self.no_header(false_response_double_quotes_2), resp_raw_first_no_header)
                    true_score_double_quotes_2 = self.get_score(self.no_header(true_response_double_quotes_2), resp_raw_first_no_header)
                    if false_score_double_quotes_2 <= self.similar and true_score_double_quotes_2 > self.similar:
                        self.logger.critical(
                            '[+] 确认存在Bool(str double_quotes)型SQL注入，false_score={}, true_score={}'.format(false_score_double_quotes_2, true_score_double_quotes_2))
                        self.db.save(
                            "insert into sql_bool (`host`,`first_req`,`first_resp`,`bool_true_req`,`bool_true_resp`, `bool_false_req`, `bool_false_resp`, `payload`, risk) VALUES ('{}','{}','{}','{}','{}','{}','{}','{}',{})".format(
                                request_data['host'], escape_string(req_raw_first), escape_string(resp_raw_first),
                                escape_string(self.wapper.generateRequest(true_request_double_quotes_2)),
                                escape_string(true_response_double_quotes_2),
                                escape_string(self.wapper.generateRequest(false_request_double_quotes_2)),
                                escape_string(false_response_double_quotes_2),
                                escape_string(
                                    self.payload_str(self.bool_double_quotes_tuple_second, false_score_double_quotes_2, true_score_double_quotes_2)), 1))
                    else:
                        self.reportFlag = True
                        self.logger.critical(
                            '[+] 疑似存在Bool(str double_quotes)型SQL注入，false_score={}, true_score={}, true_score_1={}, true_score_1_2={}'.format(false_score_double_quotes, true_score_double_quotes,true_score_double_quotes_1,true_score_double_quotes_1_2))
                        self.db.save(
                            "insert into sql_bool (`host`,`first_req`,`first_resp`,`bool_true_req`,`bool_true_resp`, `bool_false_req`, `bool_false_resp`, `payload`, risk) VALUES ('{}','{}','{}','{}','{}','{}','{}','{}',{})".format(
                                request_data['host'], escape_string(req_raw_first), escape_string(resp_raw_first),
                                escape_string(self.wapper.generateRequest(true_request_double_quotes)), escape_string(true_response_double_quotes),
                                escape_string(self.wapper.generateRequest(false_request_double_quotes)),
                                escape_string(false_response_double_quotes),
                                escape_string(self.payload_str(self.bool_double_quotes_tuple, false_score_double_quotes, true_score_double_quotes)+" === " +str(true_score_double_quotes_1) +" === " +str(true_score_double_quotes_1_2)),0))


            if len(set({strFlag, intFlag, orderFlag, strdouble_quotesFlag})) == 1:
                req_raw_repeat, resp_raw_repeat = self.wapper.generate_request_for_first(request_data)
                if resp_raw_first_no_header != self.no_header(resp_raw_repeat):
                    resp = self.wapper.generateResponse(self.wapper.processRequest(true_request_2)) # '||'
                    bool_str_list = self.no_header_list([resp_raw_first,false_response,true_response,resp,resp_raw_repeat])
                    if self.calculation(bool_str_list) == [1]:
                        self.reportFlag = True
                        self.logger.critical('[+] RANDOM -> 疑似存在Bool(str)型SQL注入')
                        self.db.save("insert into sql_bool (host , first_req,first_resp,bool_true_req, bool_true_resp, payload, risk) values ('{}','{}','{}','{}','{}','{}','{}')".format(request_data['host'],escape_string(req_raw_first), escape_string(resp_raw_first),escape_string(self.wapper.generateRequest(true_request_2)), escape_string(resp), escape_string(self.payload_rdm(self.bool_rdm[0])), 0))
                    else:
                        resp_1 = self.wapper.generateResponse(self.wapper.processRequest(false_request_4)) # '-x'
                        resp_2 = self.wapper.generateResponse(self.wapper.processRequest(true_request_4))  # '-0'
                        resp_3 = self.wapper.generateResponse(self.wapper.processRequest(true_request_4_1)) # -false
                        bool_int_list = self.no_header_list([resp_raw_first,resp_1, resp_2, resp_3,resp_raw_repeat])
                        if self.calculation(bool_int_list) == [1]:
                            self.reportFlag = True
                            self.logger.critical('[+] RANDOM -> 疑似存在Bool(int)型SQL注入')
                            self.db.save(
                                "insert into sql_bool (host , first_req,first_resp,bool_true_req, bool_true_resp, payload, risk) values ('{}','{}','{}','{}','{}','{}','{}')".format(
                                    request_data['host'],escape_string(req_raw_first), escape_string(resp_raw_first),escape_string(self.wapper.generateRequest(true_request_4_1)), escape_string(resp_3), escape_string(self.payload_rdm(self.bool_rdm[1])), 0))
                        else:
                            resp_o_1 = self.wapper.generateResponse(self.wapper.processRequest(false_request_5))  # ',1-x'
                            resp_o_2 = self.wapper.generateResponse(self.wapper.processRequest(true_request_5))  # ',1'
                            resp_o_3 = self.wapper.generateResponse(self.wapper.processRequest(true_request_5_1))  # ',true'
                            bool_order_list = self.no_header_list([resp_raw_first, resp_o_1, resp_o_2, resp_o_3,resp_raw_repeat])
                            if self.calculation(bool_order_list) == [1]:
                                self.reportFlag = True
                                self.logger.critical('[+] RANDOM -> 疑似存在Bool(order)型SQL注入')
                                self.db.save(
                                    "insert into sql_bool (host ,first_req,first_resp, bool_true_req, bool_true_resp, payload, risk) values ('{}','{}','{}','{}','{}','{}','{}')".format(
                                        request_data['host'],escape_string(req_raw_first), escape_string(resp_raw_first),escape_string(self.wapper.generateRequest(true_request_5_1)), escape_string(resp_o_3), escape_string(self.payload_rdm(self.bool_rdm[2])), 0))

        if self.reportFlag:
            self.fetch_sql()
        self.logger.info('[*] SQL BOOL注入探测完成')



    def fetch_sql(self):
        sql = 'select `create_time` ,`host`,`risk` ,`payload`, `bool_true_req`, `bool_true_resp` from sql_bool where to_days(create_time)=to_days(now())'
        items = self.db.get_all(sql)
        self.logger.info('[+] #####正在生成SQL BOOL注入漏洞报告#####')
        generate_html(items, self.template_name, self.vulType)
        self.logger.info('[+] #####SQL BOOL注入漏洞报告生成完成#####')
