#coding=utf-8

from lib.utils.diffpage import GetRatio

class Diffpage_score:
    def get_score(self,s1,s2):
        return GetRatio(s1, s2)
        
