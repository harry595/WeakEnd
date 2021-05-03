from __future__ import absolute_import, unicode_literals
from celery import shared_task,current_task
from celery import Celery
from .vuln_detect.vuln_code.ci import ci_attack
from .vuln_detect.vuln_code.lfi import lfi_attack
from .vuln_detect.vuln_code.rfi import rfi_attack
import json
import os
import time
from celery.states import state, PENDING, SUCCESS


app = Celery('tasks',  backend='rpc://', broker='pyamqp://guest:guest@localhost//')

@shared_task
def checkvuln(url,new_id):
    current_task.update_state(state='PROGRESS',meta={'process_percent': 50})
    result_data={}
    vuln_list=[]
    vuln_list.append(rfi_attack('http://192.168.112.130/vulnerabilities/fi/?page=include.php'))
    vuln_list.append(ci_attack('http://192.168.112.130/vulnerabilities/exec/'))
    vuln_list.append(lfi_attack('http://192.168.112.130/vulnerabilities/fi/?page=include.php','GET'))
    

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
                    "method": "POST",
                    "url": vuln_element['url'],
                    "data":vuln_element['data']
                })
    with open(os.path.dirname(os.path.realpath(__file__)) + '/detectedVuln/'+str(new_id)+'.json', 'w') as outfile:
        json.dump(result_data, outfile, indent=4)
    return True
