#!/usr/bin/python
# -*- coding:utf-8 -*-

import pymysql
from lib.utils.CommonLog import CommonLog
from conf.ConfigFileModifyHandler import Config

class DBUtil(object):
    db = None
    cursor = None

    def __init__(self):
        self.logger = CommonLog(__name__).getlog()
        self.host = Config.get_instance().get('mysql.HOST')
        self.port = int(Config.get_instance().get('mysql.PORT'))
        self.userName = Config.get_instance().get('mysql.USERNAME')
        self.password = Config.get_instance().get('mysql.PASSWD')
        self.dbName = Config.get_instance().get('mysql.DB')
        self.charsets = Config.get_instance().get('mysql.CHARSETS')

    # 链接数据库
    def get_con(self):
        """ 获取conn """
        self.db = pymysql.Connect(
            host=self.host,
            port=self.port,
            user=self.userName,
            passwd=self.password,
            db=self.dbName,
            charset=self.charsets
        )
        self.cursor = self.db.cursor()

    # 关闭链接
    def close(self):
        self.cursor.close()
        self.db.close()

    # 主键查询数据
    def get_one(self, sql):
        res = None
        try:
            self.get_con()
            self.cursor.execute(sql)
            res = self.cursor.fetchone()
            self.close()
        except Exception as e:
            self.logger.error("查询失败！" + str(e))
        return res

    # 查询列表数据
    def get_all(self, sql):
        res = None
        try:
            self.get_con()
            self.cursor.execute(sql)
            res = self.cursor.fetchall()
            self.close()
        except Exception as e:
            self.logger.error("查询失败！" + str(e))
        return res

    # 插入数据
    def __insert(self, sql):
        count = 0
        try:
            self.get_con()
            count = self.cursor.execute(sql)
            self.db.commit()
            self.close()
            #self.logger.info('数据库操作成功')
        except Exception as e:
            self.logger.error("操作失败！" + str(e))
            self.db.rollback()
        return count

    # 添加数据
    def save(self, sql):
        return self.__insert(sql)

    # 更新数据
    def update(self, sql):
        return self.__insert(sql)

    # 删除数据
    def delete(self, sql):
        return self.__insert(sql)

# if __name__ == '__main__':
#     db = DBUtil()
#     # x = db.get_one("select create_time, host, payload, request_data, response from ssrf WHERE payload='1cdc43559a111.ssrf.mabwcy.xforlog.cn'")
#     # print(x)
#     items = db.get_all(
#         "select create_time, host, payload, request_data, response from ssrf where to_days(create_time)=to_days(now()) and is_vul=1")
#     generate_html(items)


    #generate_html(report_dict)
