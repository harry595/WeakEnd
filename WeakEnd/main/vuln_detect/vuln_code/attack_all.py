from .ci import ci_attack
from .lfi import lfi_attack
from .rfi import rfi_attack
import json

def checkvuln(url):
    print(url)
    result_data={}
    vuln_list=[]
    vuln_list.append(rfi_attack('http://192.168.190.159/vulnerabilities/fi/?page=include.php'))
    vuln_list.append(ci_attack('http://192.168.190.159/vulnerabilities/exec/'))
    vuln_list.append(lfi_attack('http://192.168.190.159/vulnerabilities/fi/?page=include.php','GET'))
    for vuln_element in vuln_list:
        if vuln_element!=False:
            result_data[vuln_element['vuln']] = []
            if(vuln_element['method']=='GET'):
                result_data[vuln_element['vuln']].append({
                    "method": "GET",
                    "url": vuln_element['url']
                })
            else:
                result_data[vuln_element['vuln']].append({
                    "method": "GET",
                    "url": vuln_element['url'],
                    "data":vuln_element['data']
                })
    return result_data
