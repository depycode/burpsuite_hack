class DBMS:
    DB2 = 'IBM DB2 database'
    MSSQL = 'Microsoft SQL database'
    ORACLE = 'Oracle database'
    SYBASE = 'Sybase database'
    POSTGRE = 'PostgreSQL database'
    MYSQL = 'MySQL database'
    JAVA = 'Java connector'
    ACCESS = 'Microsoft Access database'
    INFORMIX = 'Informix database'
    INTERBASE = 'Interbase database'
    DMLDATABASE = 'DML Language database'
    SQLITE = 'SQLite database'
    UNKNOWN = 'Unknown database'


class OS(object):
    LINUX = "Linux"
    WINDOWS = "Windows"
    DARWIN = "Darwin"



class VulType(object):
    CMD_INNJECTION = "cmd_injection"
    CODE_INJECTION = "code_injection"
    XSS = "xss"
    SQLI = "sqli"
    DIRSCAN = "dirscan"
    PATH_TRAVERSAL = "path_traversal"
    XXE = "xxe"
    BRUTE_FORCE = "brute_force"
    JSONP = "jsonp"
    SSRF = "SSRF"
    BASELINE = "baseline"
    REDIRECT = "redirect"
    CRLF = "crlf"
    SENSITIVE = "sensitive"
    SMUGGLING = 'smuggling'
    SSTI = 'ssti'
    UNAUTH = 'unauth'
    SQLI_ERROR_BASE = 'SQLERROR'
    SQLI_BOOL_BASE = 'SQLBOOL'
