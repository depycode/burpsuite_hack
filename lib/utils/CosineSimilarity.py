# -*- coding: utf-8 -*-

# 正则包
import re
# html 包
import html
# 自然语言处理包
import jieba
import jieba.analyse
# 机器学习包
from sklearn.metrics.pairwise import cosine_similarity
import os


class CosineSimilarity(object):
    """
    余弦相似度
    """
    def __init__(self):
        filePath = os.path.join(os.path.dirname(__file__), "files/stopwords.txt")
        jieba.analyse.set_stop_words(filePath)

    @staticmethod
    def extract_keyword(content):  # 提取关键词
        # 正则过滤 html 标签
        re_exp = re.compile(r'(<style>.*?</style>)|(<[^>]+>)', re.S)
        content = re_exp.sub(' ', content)
        # html 转义符实体化
        content = html.unescape(content)
        # 切割
        seg = [i for i in jieba.cut(content, cut_all=True) if i != '']
        # 提取关键词
        keywords = jieba.analyse.extract_tags("|".join(seg), topK=1000, withWeight=False)
        return keywords

    @staticmethod
    def one_hot(word_dict, keywords):  # oneHot编码
        # cut_code = [word_dict[word] for word in keywords]
        cut_code = [0]*len(word_dict)
        for word in keywords:
            cut_code[word_dict[word]] += 1
        return cut_code

    def get_score(self,s1,s2):
        # 去除停用词
        filePath = os.path.join(os.path.dirname(__file__), "files/stopwords.txt")
        jieba.analyse.set_stop_words(filePath)
        # 提取关键词
        keywords1 = self.extract_keyword(s1)
        keywords2 = self.extract_keyword(s2)
        # 词的并集
        union = set(keywords1).union(set(keywords2))
        # 编码
        word_dict = {}
        i = 0
        for word in union:
            word_dict[word] = i
            i += 1
        # oneHot编码
        s1_cut_code = self.one_hot(word_dict, keywords1)
        s2_cut_code = self.one_hot(word_dict, keywords2)
        # 余弦相似度计算
        sample = [s1_cut_code, s2_cut_code]
        # 除零处理
        try:
            sim = cosine_similarity(sample)
            return sim[1][0]
        except Exception as e:
            print(e)
            return 0.0


if __name__ == '__main__':
    list_html = [
        '<pre>ID:1<br /><pre>first_name:admin<br /><pre>last_name:admin<br />JDS6xwWlYPZLcsNm-avhnR9fqd3KHMyrX0AFQ25eEkI71_4Gi8TU',
        '<pre>ID:1<br /><pre>first_name:admin<br /><pre>last_name:admin<br />eWtsifuM03h-TDYXj7NqgI4vGOSVLr5KmPHk_ZC',
        'error!AndyprcImbxKfFswzl7VJit6-DT',
        '<pre>database error...    C4oXG_BtKd2WQF3iNpSOJxRAVlPZ0aEj1Hg9svf-UThzMLe</pre>',
        '<pre>ID:1<br /><pre>first_name:admin<br /><pre>last_name:admin<br />o0LaSKk_WGyEdqZ6ftT2X835DlHReJwVAFYBmUx']
    c = CosineSimilarity()
    print(c.get_score(list_html[0], list_html[1]))


# # 测试
# if __name__ == '__main__':
#     list_html = ["""<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
# "http://www.w3.org/TR/html4/loose.dtd">
# <html><!-- InstanceBegin template="/Templates/main_dynamic_template.dwt.php" codeOutsideHTMLIsLocked="false" -->
# <head>
# <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-2">
#
# <!-- InstanceBeginEditable name="document_title_rgn" -->
# <title>artists</title>
# <!-- InstanceEndEditable -->
# <link rel="stylesheet" href="style.css" type="text/css">
# <!-- InstanceBeginEditable name="headers_rgn" -->
# <!-- here goes headers headers -->
# <!-- InstanceEndEditable -->
# <script language="JavaScript" type="text/JavaScript">
# <!--
# function MM_reloadPage(init) {  //reloads the window if Nav4 resized
#   if (init==true) with (navigator) {if ((appName=="Netscape")&&(parseInt(appVersion)==4)) {
#     document.MM_pgW=innerWidth; document.MM_pgH=innerHeight; onresize=MM_reloadPage; }}
#   else if (innerWidth!=document.MM_pgW || innerHeight!=document.MM_pgH) location.reload();
# }
# MM_reloadPage(true);
# //-->
# </script>
#
# </head>
# <body>
# <div id="mainLayer" style="position:absolute; width:700px; z-index:1">
# <div id="masthead">
#   <h1 id="siteName"><a href="https://www.acunetix.com/"><img src="images/logo.gif" width="306" height="38" border="0" alt="Acunetix website security"></a></h1>
#   <h6 id="siteInfo">TEST and Demonstration site for <a href="https://www.acunetix.com/vulnerability-scanner/">Acunetix Web Vulnerability Scanner</a></h6>
#   <div id="globalNav">
#       	<table border="0" cellpadding="0" cellspacing="0" width="100%"><tr>
# 	<td align="left">
# 		<a href="index.php">home</a> | <a href="categories.php">categories</a> | <a href="artists.php">artists
# 		</a> | <a href="disclaimer.php">disclaimer</a> | <a href="cart.php">your cart</a> |
# 		<a href="guestbook.php">guestbook</a> |
# 		<a href="AJAX/index.php">AJAX Demo</a>
# 	</td>
# 	<td align="right">
# 		</td>
# 	</tr></table>
#   </div>
# </div>
# <!-- end masthead -->
#
# <!-- begin content -->
# <!-- InstanceBeginEditable name="content_rgn" -->
# <div id="content">
#
# Warning: mysql_fetch_array() expects parameter 1 to be resource, boolean given in /hj/var/www/artists.php on line 62
#
# </div>
# <!-- InstanceEndEditable -->
# <!--end content -->
#
# <div id="navBar">
#   <div id="search">
#     <form action="search.php?test=query" method="post">
#       <label>search art</label>
#       <input name="searchFor" type="text" size="10">
#       <input name="goButton" type="submit" value="go">
#     </form>
#   </div>
#   <div id="sectionLinks">
#     <ul>
#       <li><a href="categories.php">Browse categories</a></li>
#       <li><a href="artists.php">Browse artists</a></li>
#       <li><a href="cart.php">Your cart</a></li>
#       <li><a href="login.php">Signup</a></li>
# 	  <li><a href="userinfo.php">Your profile</a></li>
# 	  <li><a href="guestbook.php">Our guestbook</a></li>
# 		<li><a href="AJAX/index.php">AJAX Demo</a></li>
# 	  </li>
#     </ul>
#   </div>
#   <div class="relatedLinks">
#     <h3>Links</h3>
#     <ul>
#       <li><a href="http://www.acunetix.com">Security art</a></li>
# 	  <li><a href="https://www.acunetix.com/vulnerability-scanner/php-security-scanner/">PHP scanner</a></li>
# 	  <li><a href="https://www.acunetix.com/blog/articles/prevent-sql-injection-vulnerabilities-in-php-applications/">PHP vuln help</a></li>
# 	  <li><a href="http://www.eclectasy.com/Fractal-Explorer/index.html">Fractal Explorer</a></li>
#     </ul>
#   </div>
#   <div id="advert">
#     <p>
#       <object classid="clsid:D27CDB6E-AE6D-11cf-96B8-444553540000" codebase="http://download.macromedia.com/pub/shockwave/cabs/flash/swflash.cab#version=6,0,29,0" width="107" height="66">
#         <param name="movie" value="Flash/add.swf">
#         <param name=quality value=high>
#         <embed src="Flash/add.swf" quality=high pluginspage="http://www.macromedia.com/shockwave/download/index.cgi?P1_Prod_Version=ShockwaveFlash" type="application/x-shockwave-flash" width="107" height="66"></embed>
#       </object>
#     </p>
#   </div>
# </div>
#
# <!--end navbar -->
# <div id="siteInfo">  <a href="http://www.acunetix.com">About Us</a> | <a href="privacy.php">Privacy Policy</a> | <a href="mailto:wvs@acunetix.com">Contact Us</a> | &copy;2019
#   Acunetix Ltd
# </div>
# <br>
# <div style="background-color:lightgray;width:100%;text-align:center;font-size:12px;padding:1px">
# <p style="padding-left:5%;padding-right:5%"><b>Warning</b>: This is not a real shop. This is an example PHP application, which is intentionally vulnerable to web attacks. It is intended to help you test Acunetix. It also helps you understand how developer errors and bad configuration may let someone break into your website. You can use it to test other tools and your manual hacking skills as well. Tip: Look for potential SQL Injections, Cross-site Scripting (XSS), and Cross-site Request Forgery (CSRF), and more.</p>
# </div>
# </div>
# </body>
# <!-- InstanceEnd --></html>""","""<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
# "http://www.w3.org/TR/html4/loose.dtd">
# <html><!-- InstanceBegin template="/Templates/main_dynamic_template.dwt.php" codeOutsideHTMLIsLocked="false" -->
# <head>
# <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-2">
#
# <!-- InstanceBeginEditable name="document_title_rgn" -->
# <title>artists</title>
# <!-- InstanceEndEditable -->
# <link rel="stylesheet" href="style.css" type="text/css">
# <!-- InstanceBeginEditable name="headers_rgn" -->
# <!-- here goes headers headers -->
# <!-- InstanceEndEditable -->
# <script language="JavaScript" type="text/JavaScript">
# <!--
# function MM_reloadPage(init) {  //reloads the window if Nav4 resized
#   if (init==true) with (navigator) {if ((appName=="Netscape")&&(parseInt(appVersion)==4)) {
#     document.MM_pgW=innerWidth; document.MM_pgH=innerHeight; onresize=MM_reloadPage; }}
#   else if (innerWidth!=document.MM_pgW || innerHeight!=document.MM_pgH) location.reload();
# }
# MM_reloadPage(true);
# //-->
# </script>
#
# </head>
# <body>
# <div id="mainLayer" style="position:absolute; width:700px; z-index:1">
# <div id="masthead">
#   <h1 id="siteName"><a href="https://www.acunetix.com/"><img src="images/logo.gif" width="306" height="38" border="0" alt="Acunetix website security"></a></h1>
#   <h6 id="siteInfo">TEST and Demonstration site for <a href="https://www.acunetix.com/vulnerability-scanner/">Acunetix Web Vulnerability Scanner</a></h6>
#   <div id="globalNav">
#       	<table border="0" cellpadding="0" cellspacing="0" width="100%"><tr>
# 	<td align="left">
# 		<a href="index.php">home</a> | <a href="categories.php">categories</a> | <a href="artists.php">artists
# 		</a> | <a href="disclaimer.php">disclaimer</a> | <a href="cart.php">your cart</a> |
# 		<a href="guestbook.php">guestbook</a> |
# 		<a href="AJAX/index.php">AJAX Demo</a>
# 	</td>
# 	<td align="right">
# 		</td>
# 	</tr></table>
#   </div>
# </div>
# <!-- end masthead -->
#
# <!-- begin content -->
# <!-- InstanceBeginEditable name="content_rgn" -->
# <div id="content">
# 	<h2 id='pageName'>artist: r4w8173</h2><div class='story'><p><p>
# Lorem ipsum dolor sit amet, consectetuer adipiscing elit. Donec molestie.
#     Sed aliquam sem ut arcu. Phasellus sollicitudin. Vestibulum condimentum facilisis
#     nulla. In hac habitasse platea dictumst. Nulla nonummy. Cras quis libero.
#     Cras venenatis. Aliquam posuere lobortis pede. Nullam fringilla urna id leo.
#     Praesent aliquet pretium erat. Praesent non odio. Pellentesque a magna a
#     mauris vulputate lacinia. Aenean viverra. Class aptent taciti sociosqu ad
#     litora torquent per conubia nostra, per inceptos hymenaeos. Aliquam lacus.
#     Mauris magna eros, semper a, tempor et, rutrum et, tortor.
# </p>
# <p>
# Lorem ipsum dolor sit amet, consectetuer adipiscing elit. Donec molestie.
#     Sed aliquam sem ut arcu. Phasellus sollicitudin. Vestibulum condimentum facilisis
#     nulla. In hac habitasse platea dictumst. Nulla nonummy. Cras quis libero.
#     Cras venenatis. Aliquam posuere lobortis pede. Nullam fringilla urna id leo.
#     Praesent aliquet pretium erat. Praesent non odio. Pellentesque a magna a
#     mauris vulputate lacinia. Aenean viverra. Class aptent taciti sociosqu ad
#     litora torquent per conubia nostra, per inceptos hymenaeos. Aliquam lacus.
#     Mauris magna eros, semper a, tempor et, rutrum et, tortor.
# </p></p><p><a href='listproducts.php?artist=1'>view pictures of the artist</a></p><p><a href='#' onClick="window.open('./comment.php?aid=1','comment','width=500,height=400')">comment on this artist</a></p></div>
# </div>
# <!-- InstanceEndEditable -->
# <!--end content -->
#
# <div id="navBar">
#   <div id="search">
#     <form action="search.php?test=query" method="post">
#       <label>search art</label>
#       <input name="searchFor" type="text" size="10">
#       <input name="goButton" type="submit" value="go">
#     </form>
#   </div>
#   <div id="sectionLinks">
#     <ul>
#       <li><a href="categories.php">Browse categories</a></li>
#       <li><a href="artists.php">Browse artists</a></li>
#       <li><a href="cart.php">Your cart</a></li>
#       <li><a href="login.php">Signup</a></li>
# 	  <li><a href="userinfo.php">Your profile</a></li>
# 	  <li><a href="guestbook.php">Our guestbook</a></li>
# 		<li><a href="AJAX/index.php">AJAX Demo</a></li>
# 	  </li>
#     </ul>
#   </div>
#   <div class="relatedLinks">
#     <h3>Links</h3>
#     <ul>
#       <li><a href="http://www.acunetix.com">Security art</a></li>
# 	  <li><a href="https://www.acunetix.com/vulnerability-scanner/php-security-scanner/">PHP scanner</a></li>
# 	  <li><a href="https://www.acunetix.com/blog/articles/prevent-sql-injection-vulnerabilities-in-php-applications/">PHP vuln help</a></li>
# 	  <li><a href="http://www.eclectasy.com/Fractal-Explorer/index.html">Fractal Explorer</a></li>
#     </ul>
#   </div>
#   <div id="advert">
#     <p>
#       <object classid="clsid:D27CDB6E-AE6D-11cf-96B8-444553540000" codebase="http://download.macromedia.com/pub/shockwave/cabs/flash/swflash.cab#version=6,0,29,0" width="107" height="66">
#         <param name="movie" value="Flash/add.swf">
#         <param name=quality value=high>
#         <embed src="Flash/add.swf" quality=high pluginspage="http://www.macromedia.com/shockwave/download/index.cgi?P1_Prod_Version=ShockwaveFlash" type="application/x-shockwave-flash" width="107" height="66"></embed>
#       </object>
#     </p>
#   </div>
# </div>
#
# <!--end navbar -->
# <div id="siteInfo">  <a href="http://www.acunetix.com">About Us</a> | <a href="privacy.php">Privacy Policy</a> | <a href="mailto:wvs@acunetix.com">Contact Us</a> | &copy;2019
#   Acunetix Ltd
# </div>
# <br>
# <div style="background-color:lightgray;width:100%;text-align:center;font-size:12px;padding:1px">
# <p style="padding-left:5%;padding-right:5%"><b>Warning</b>: This is not a real shop. This is an example PHP application, which is intentionally vulnerable to web attacks. It is intended to help you test Acunetix. It also helps you understand how developer errors and bad configuration may let someone break into your website. You can use it to test other tools and your manual hacking skills as well. Tip: Look for potential SQL Injections, Cross-site Scripting (XSS), and Cross-site Request Forgery (CSRF), and more.</p>
# </div>
# </div>
# </body>
# <!-- InstanceEnd --></html>"""]
#     list_html2 = ['false','false']
#     similarity = CosineSimilarity(list_html[0], list_html[1])
#     similarity = similarity.main()
#     print('相似度: %.2f%%' % (similarity*100))