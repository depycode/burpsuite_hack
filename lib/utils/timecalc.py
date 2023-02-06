import time
from lib.utils.CommonLog import CommonLog

logger = CommonLog(__name__).getlog()

def get_time(f):

    def inner(*arg,**kwarg):
        s_time = time.time()
        res = f(*arg,**kwarg)
        e_time = time.time()
        logger.info('[*] 耗时：{}秒'.format(e_time - s_time))
        return res
    return inner