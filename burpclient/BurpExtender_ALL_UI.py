#coding=utf-8
from burp import IBurpExtender
from burp import IContextMenuFactory
from java.io import PrintWriter
from burp import IHttpListener
from javax import swing
from burp import ITab

from javax.swing import JMenuItem
from java.util import List, ArrayList
import re
import socket
import json


class BurpExtender(IBurpExtender, IHttpListener, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        callbacks.registerHttpListener(self)
        callbacks.setExtensionName("BurpSuite_Hack")
        self.scan_host = ()
        self.static_suffix = ()
        self.black_host = []
        self.udp_server_host = ''
        self.udp_server_port = ''
        
        
        #jPanel
        self._jPanel = swing.JPanel()
        
        #需要扫描的host
        boxVertical = swing.Box.createVerticalBox()
        boxHorizontal = swing.Box.createHorizontalBox()
        boxHorizontal.add(swing.JLabel('SCAN_HOST:'))
        self._scan_host = swing.JTextField('.qq.com|.tencent.com', 50)
        boxHorizontal.add(self._scan_host)
        boxVertical.add(boxHorizontal)
        boxVertical.add(swing.Box.createVerticalStrut(10))
        
        # 静态后缀
        boxHorizontal = swing.Box.createHorizontalBox()
        boxHorizontal.add(swing.JLabel('STATIC_SUFFIX:'))
        self._static_suffix = swing.JTextField('.jpg|.js|.css|.ico|.gif|.swf|woff|.png|.jpeg|.woff2|.svg|.mp4|.flv|.map|.json|.txt|.svg|.ttf|.ttf2|.bin', 50)
        boxHorizontal.add(self._static_suffix)
        boxVertical.add(boxHorizontal)
        boxVertical.add(swing.Box.createVerticalStrut(10))
        
        # 黑名单host
        boxHorizontal = swing.Box.createHorizontalBox()
        boxHorizontal.add(swing.JLabel('BLACK_HOST:'))
        self._black_host = swing.JTextField('otheve.beacon.qq.com|h5vv6.video.qq.com', 50)
        boxHorizontal.add(self._black_host)
        boxVertical.add(boxHorizontal)
        boxVertical.add(swing.Box.createVerticalStrut(10))
        
        #udp服务端host 必选
        boxHorizontal = swing.Box.createHorizontalBox()
        boxHorizontal.add(swing.JLabel('UDP_SERVER_HOST *:'))
        self._udp_server_host = swing.JTextField('127.0.0.1', 50)
        boxHorizontal.add(self._udp_server_host)
        boxVertical.add(boxHorizontal)
        boxVertical.add(swing.Box.createVerticalStrut(10))
        
        #udp服务端port 必选
        boxHorizontal = swing.Box.createHorizontalBox()
        boxHorizontal.add(swing.JLabel('UDP_SERVER_PORT *:'))
        self._udp_server_port = swing.JTextField('9999', 50)
        boxHorizontal.add(self._udp_server_port)
        boxVertical.add(boxHorizontal)
        boxVertical.add(swing.Box.createVerticalStrut(10))
        
        #第一次加载完插件后必须点一次SET
        boxHorizontal = swing.Box.createHorizontalBox()
        setButton = swing.JButton('SET *',actionPerformed=self.setConfig)
        boxHorizontal.add(setButton)
        boxHorizontal.add(swing.Box.createHorizontalStrut(30))
        clearButton = swing.JButton('CLEAR',actionPerformed=self.clearConfig)
        boxHorizontal.add(clearButton)
        boxVertical.add(boxHorizontal)

        self._jPanel.add(boxVertical)
        # add the custom tab to Burp's UI
        callbacks.addSuiteTab(self)
        

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if toolFlag == self._callbacks.TOOL_PROXY and messageIsRequest:
            #print self.scan_host
            #print self.static_suffix
            #print self.black_host
            #print self.udp_server_host
            #print self.udp_server_port
            
            httpService = messageInfo.getHttpService()
            host = httpService.getHost()
            analyzeRequest = self._helpers.analyzeRequest(messageInfo)
            full_url = analyzeRequest.getUrl().toString()
            params = analyzeRequest.getParameters()
            method = analyzeRequest.getMethod()
            if self.getParamaters(params,0) or self.getParamaters(params, 1) or messageInfo.getRequest()[analyzeRequest.getBodyOffset():].tostring():
                if method in ['GET','POST'] and not full_url.split('?')[0].endswith(self.static_suffix) and host not in self.black_host:
                    # scan_host=() 时扫描所有，scan_host=('.qq.com','aa.com') 时仅扫描以qq.com和aa.com结尾的域名
                    if len(self.scan_host)>0:
                        if host.endswith(self.scan_host):
                            self.parseRequest(messageInfo)
                    else:
                        self.parseRequest(messageInfo)

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
        s.connect((self.udp_server_host, self.udp_server_port))
        try:
            s.sendall(str(send_data).encode('utf-8'))
        except Exception as e:
            self.stdout.println(e)
        finally:
            s.close()
            
    # implement ITab
    def getTabCaption(self): 
        return 'BurpSuite_Hack'
    
    def getUiComponent(self):
        return self._jPanel

    def setConfig(self, button):
        self.scan_host = tuple(self._scan_host.getText().strip().split('|')) if self._scan_host.getText().strip() else ()
        self.static_suffix = tuple(self._static_suffix.getText().strip().split('|')) if self._static_suffix.getText().strip() else ()
        self.black_host = self._black_host.getText().strip().split('|') if self._static_suffix.getText().strip() else []
        self.udp_server_host = self._udp_server_host.getText().strip()
        self.udp_server_port = int(self._udp_server_port.getText())

    def clearConfig(self, button):
        self._scan_host.setText('')
        self._static_suffix.setText('')
        self._black_host.setText('')
        self._udp_server_host.setText('')
        self._udp_server_port.setText('')
