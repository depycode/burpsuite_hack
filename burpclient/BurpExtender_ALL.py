from burp import IBurpExtender
from burp import IContextMenuFactory
from java.io import PrintWriter
from burp import IHttpListener

from javax.swing import JMenuItem
from java.util import List, ArrayList
import re
import socket
import json


class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        callbacks.registerHttpListener(self)
        callbacks.setExtensionName("SQLI")
        self.scan_host = ('.qq.com','.tencent.com','.tencent-cloud.com','tencentcs.com','.qcloud.com')
        #self.scan_host = ('.paas.cmbchina.com','.bcs.cmbchina.com','.bas.cmbchina.com','.alb-sz.cmbchina.com')
        self.static_url = ('.jpg','.js','.css','.ico','.gif','.swf','woff','.png','.jpeg','.woff2','.svg','.mp4','.flv','.map','.json','.txt','.svg','.ttf','.ttf2','.bin')
        self.black_host = ['otheve.beacon.qq.com','h5vv6.video.qq.com','mbmodule-openapi.paas.cmbchina.com','searchagency.paas.cmbchina.com']

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if toolFlag == self._callbacks.TOOL_PROXY and messageIsRequest:
            httpService = messageInfo.getHttpService()
            host = httpService.getHost()
            analyzeRequest = self._helpers.analyzeRequest(messageInfo)
            full_url = analyzeRequest.getUrl().toString()
            params = analyzeRequest.getParameters()
            method = analyzeRequest.getMethod()
            if self.getParamaters(params,0) or self.getParamaters(params, 1) or messageInfo.getRequest()[analyzeRequest.getBodyOffset():].tostring():
                if host.endswith(self.scan_host)  and method in ['GET','POST'] and not full_url.split('?')[0].endswith(self.static_url) and host not in self.black_host:
                    self.parseRequest(messageInfo)


    # def createMenuItems(self, invocation):
    #     menu_list = ArrayList()
    #     messageInfo = invocation.getSelectedMessages()[0]
    #     if invocation.getToolFlag() == 64 or invocation.getToolFlag() == 4:
    #         menu_list.add(
    #             JMenuItem("SQLI Scanner", None, actionPerformed=lambda x, mess=messageInfo: self.parseRequest(mess)))
    #     return menu_list

    # PARAM_URL 0 , PARAM_BODY 1
    def getParamaters(self, params, ptype):
        params_dict = {}
        for i in params:
            if i.getType() == ptype:
                # params_dict[i.getName()] = json.loads(self._helpers.urlDecode(i.getValue()))
                params_dict[i.getName()] = self._helpers.urlDecode(i.getValue())
        return params_dict

    def parseRequest(self, messageInfo):
        httpService = messageInfo.getHttpService()
        analyzeRequest = self._helpers.analyzeRequest(messageInfo)
        host = httpService.getHost()
        port = httpService.getPort()
        protocol = httpService.getProtocol()
        method = analyzeRequest.getMethod()
        full_url = analyzeRequest.getUrl().toString()
        bp_headers = analyzeRequest.getHeaders()
        content_type = analyzeRequest.getContentType()
        # self.stdout.println(host + str(port) + protocol)
        reqUri, bp1_headers = '\r\n'.join(bp_headers).split('\r\n', 1)
        headers = dict(re.findall(r"(?P<name>.*?): (?P<value>.*?)\r\n", bp1_headers + '\r\n'))
        # self.stdout.println(headers)
        body = messageInfo.getRequest()[analyzeRequest.getBodyOffset():].tostring() if messageInfo.getRequest()[
                                                                                       analyzeRequest.getBodyOffset():].tostring() else '{}'
        params = analyzeRequest.getParameters()
        paramsINURL = self.getParamaters(params, 0)
        paramsINBODY = self.getParamaters(params, 1)
        send_data = {}
        send_data['host'] = host
        send_data['port'] = port
        send_data['protocol'] = protocol
        send_data['method'] = method
        send_data['full_url'] = full_url
        send_data['headers'] = headers
        send_data['content_type'] = content_type
        send_data['body'] = body
        send_data['param_in_url'] = paramsINURL
        send_data['param_in_body'] = paramsINBODY
        #self.stdout.println(send_data)

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        #扫描端监听的端口和地址
        s.connect(('127.0.0.1', 32743))
        try:
            s.sendall(str(send_data).encode('utf-8'))
        except Exception as e:
            self.stdout.println(e)
        finally:
            # close 
            s.close()

