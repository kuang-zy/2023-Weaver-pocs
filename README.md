# 2023-Weaver-pocs
## 2023泛微0A漏洞poc检测工具

### 支持检测漏洞
泛微 E-Office文件上传漏洞（CVE-2023-2523)  
泛微 E-Office文件上传漏洞(CVE-2023-2648)  
泛微E-Cology SQL注入漏洞(CVE-2023-15672)  
泛微OA E-Cology9未授权SQL注入漏洞(CNVD-2023-12632)  
泛微OA e-cology前台接口SQL注入漏洞  
泛微 e-cology  ofsLogin任意用户登录漏洞  
泛微E-Cology /CheckServer.jsp 路径SQL注入漏洞(QVD-2023-9849)  
泛微E-Office UserSelect未授权访问漏洞  
泛微OA E-Office mysql_config.ini 数据库信息泄漏漏洞  

### 环境
**Python3环境，依赖库**  
import requests  
import sys  
import re  
import base64  

### 使用
-h              输出本帮助菜单  
-u url          单个url进行poc检测,例：-u https://www.baidu.com/ (注意：最后的"/"一定要加上)  
-f filename     批量检测，一行放一个url保存到txt中,例：-f targets.txt  
![84b519d98cf27fdb2f1cd5e3888b55f](https://github.com/kuang-zy/2023-Weaver-pocs/assets/53716757/62579ca0-8dcf-4f9e-ad05-46dd65865977)

