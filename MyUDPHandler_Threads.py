import socketserver
import json
from lib.utils.HttpWappalyzer import HttpWappalyzer
from conf.ConfigFileModifyHandler import *
import copy
import queue
from socketserver import UDPServer
from socketserver import ThreadingMixIn
from socketserver import BaseRequestHandler
from lib.plugins.ssrf import SSRF
from lib.plugins.rce import RCE
from lib.plugins.sql_error import SQLError
from lib.plugins.sql_bool import SQLBool
from lib.utils.CosineSimilarity import CosineSimilarity
from conf.ConfigFileModifyHandler import Config
import hashlib
import threading



class MyUDPServer(ThreadingMixIn, UDPServer):
    def __init__(self, server_address, RequestHandlerClass, bind_and_activate=True, queue=None):
        self.queue = queue
        UDPServer.__init__(self, server_address, RequestHandlerClass, bind_and_activate=bind_and_activate)


class MyUDPHandler(socketserver.BaseRequestHandler):
    def __init__(self, request, client_address, server):
        self.queue = server.queue
        BaseRequestHandler.__init__(self, request, client_address, server)

    def parse(self,p):
        x = {}
        for k,v in p.items():
            try:
                v1 = json.loads(v)
            except:
                v1 = v
            x[k] = v1
        return x

    def handle(self):  # 必须要有handle方法；所有处理必须通过handle方法实现
        # self.request is the TCP socket connected to the client
        self.data = self.request[0].strip()
        data_dict = eval(self.data.decode('utf-8'))
        data_dict['param_in_url'] = self.parse(data_dict['param_in_url'])
        data_dict['param_in_body'] = self.parse(data_dict['param_in_body'])
        self.queue.put(data_dict)

class DeDuplicate(object):
    def __init__(self,duplicate_list,logger):
        self.duplicate_list = duplicate_list
        self.logger = logger
        self.duplicate_params = Config.get_instance().get("app.DUPLICATE_PARAMS").split('|')
        self.duplicate_length = int(Config.get_instance().get('app.DUPLICATE_LEGNTH'))
        self.black_host_list =  Config.get_instance().get("app.BLACK_HOSTS").split('|')

    def getHash(self,hashString):
        m = hashlib.md5(hashString.encode(encoding='utf-8'))
        return m.hexdigest()  # 转化为16进制打印md5值

    def pop_param(self, param_list):
        """
        去掉黑名单的headers
        :param headers_dict:
        :return:
        """
        keys = param_list.keys()
        for key in list(keys):
            if key in self.duplicate_params:
                param_list.pop(key)

        return param_list

    def query(self,request,http):
        host = request['host']
        #print(host)
        #print(self.black_host_list)
        if host in self.black_host_list:
            self.logger.info('黑名单host, pass')
            return False
        uri = http.parseUrl(request['full_url'])
        content_type = request['content_type']
        param_in_body = request['param_in_body']
        param_in_url = request['param_in_url']
        try:
            #self.logger.info(request['body'])
            body = json.loads(request['body'])
        except:
            body = {}
        tmpObj = [param_in_body, param_in_url,body]
        listobj = list(map(self.pop_param, tmpObj))
        hashString = uri + str(content_type) + ''.join([str(i) for i in listobj])
        #self.logger.info("----" + hashString)
        md5 = self.getHash(hashString)
        if md5 in self.duplicate_list:
            self.logger.info('重复请求')
            return False
        elif len(self.duplicate_list)<=self.duplicate_length:
            self.duplicate_list.append(md5)
            return True
        else:
            self.duplicate_list.clear()
            self.logger.info('exceed max length ,clear md5 list')
            self.duplicate_list.append(md5)
            return True


def worker(q):
    while True:    
        logger.info(f'队列长度: {q.qsize()}')
        logger.info(f'当前运行的线程数量: {threading.active_count()}')
        data = q.get()
        scan_vul(data)

def scan_vul(data):
    lock = threading.RLock()
    deDuplicate = DeDuplicate(deplicate_list, logger)
    http = HttpWappalyzer()
    lock.acquire()
    try:
        status = deDuplicate.query(copy.deepcopy(data), http)
    except:
        status = True
    lock.release()
    if status:
        ssrf = SSRF(http)
        sql = SQLError(http)
        content_type = data['content_type']
        sqlbool = SQLBool(http, model, content_type)

        try:
            ssrf.scan(copy.deepcopy(data))
        except Exception as e:
            logger.error(str(e))
            pass
        try:    
            sql.scan(copy.deepcopy(data))
        except Exception as e:
            logger.error(str(e))
            pass
        try:
            sqlbool.scan(copy.deepcopy(data))
        except Exception as e:
            logger.error(str(e))
            pass


if __name__ == "__main__":
    logger = CommonLog(__name__).getlog()
    HOST, PORT = "0.0.0.0", 32743
    queue = queue.Queue()
    model = CosineSimilarity()
    server = MyUDPServer((HOST, PORT), MyUDPHandler, queue=queue)  # 实例化一个多线程UDPServer
    server.max_packet_size = 8192 * 20
    # Start the server
    SERVER_THREAD = threading.Thread(target=server.serve_forever)
    SERVER_THREAD.daemon = True
    SERVER_THREAD.start()

    #http = HttpWappalyzer()
    deplicate_list = []
    #deDuplicate = DeDuplicate(deplicate_list, logger)

    logger.info(f'----- udp server start at {HOST} port {PORT} ----')
    thread_num = 10
    threads = []
    for i in range(thread_num):
        t = threading.Thread(target=worker, args=(queue,))
        threads.append(t)

    for i in range(thread_num):
        threads[i].start()

    for i in range(thread_num):
        threads[i].join()
