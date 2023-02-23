#!/usr/bin/python
# -*- coding:utf-8 -*-

import logging
import time
import os
import colorlog


log_colors_config = {
    'DEBUG': 'cyan',
    'INFO': 'green',
    'WARNING': 'yellow',
    'ERROR': 'cyan',
    'CRITICAL': 'bg_red',
}

class CommonLog(object):
    def __init__(self, logger=None):
        self.logger = logging.getLogger(logger)
        self.logger.setLevel(logging.DEBUG)
        self.log_time = time.strftime("%Y_%m_%d")
        file_dir = os.path.join(os.path.dirname(__file__), '../../logs')
        if not os.path.exists(file_dir):
            os.mkdir(file_dir)
        self.log_name = os.path.join(os.path.dirname(__file__), '../../logs', self.log_time + '.log')

        if not self.logger.handlers:
            fh = logging.FileHandler(self.log_name, 'a', encoding='utf-8')
            fh.setLevel(logging.INFO)

            # 再创建一个handler，用于输出到控制台
            ch = logging.StreamHandler()
            ch.setLevel(logging.INFO)

            # 定义handler的输出格式
            formatter1 = logging.Formatter('[%(asctime)s] %(filename)s->%(funcName)s line:%(lineno)d [%(levelname)s] %(message)s')
            formatter = colorlog.ColoredFormatter('%(log_color)s[%(asctime)s] %(filename)s->%(funcName)s line:%(lineno)d [%(levelname)s] %(message)s', log_colors=log_colors_config)
            fh.setFormatter(formatter1)
            ch.setFormatter(formatter)

            # 给logger添加handler
            self.logger.addHandler(fh)
            self.logger.addHandler(ch)

            fh.close()
            ch.close()

    def getlog(self):
        return self.logger
