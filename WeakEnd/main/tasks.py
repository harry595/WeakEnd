from __future__ import absolute_import, unicode_literals
from celery import shared_task,current_task
from celery import Celery
from .vuln_detect.vuln_code.ci import ci_attack
from .vuln_detect.vuln_code.lfi import lfi_attack
from .vuln_detect.vuln_code.rfi import rfi_attack
from .vuln_detect.vuln_code.sqli import sqli_attack
from .vuln_detect.vuln_code.xss import xss_attack
#from .vuln_detect.vuln_code.rfi import rfi_attack
from .vuln_detect.find_url.form_out import zetanize
import json
import time
from celery.states import state, PENDING, SUCCESS
import base64
import os, sys, urllib, re, string
from ssl import SSLError
from urllib.error import HTTPError
import requests
from urllib import parse
from urllib.parse import urlparse


app = Celery('tasks',  backend='rpc://', broker='pyamqp://guest:guest@localhost//')

@shared_task
def checkvuln(urls,cookies,level,new_id):

    current_task.update_state(state='PROGRESS',meta={'process_percent': 0})
    current_path=os.path.dirname(os.path.realpath(__file__))
    result_data={}
    with open(current_path + '/detectedVuln/'+str(new_id)+'.json', 'w') as outfile:
        outfile.write("{}")

    taskcal=100/len(urls)/10
    taskflag=0

    # 여기서 들어온 url을 for문 돌리기 여기서 171은 new_id라고 보면됨 추후 수정
    for url in urls:
        with open(current_path + '/vuln_detect/vuln_code/dirscanning/171/'+url+'_80/'+url+'_80-dynamic-unique.txt', 'r') as f:
            geturls=f.readlines()
        get_lists=[]
        for geturl in geturls:
            get_lists.append(["get",geturl.rstrip()])

        with open(current_path + '/vuln_detect/vuln_code/dirscanning/171/'+url+'_80/'+url+'_80-forms-sorted.txt', 'r') as f:
            posturls=f.readlines()
        zetanize_lists=[]

        for posturl in posturls:
            try:
                print(posturl)
                res = requests.get(posturl.rstrip(),cookies=cookies,verify=False)
                tmp_zetanize=list(zetanize(res.text).values())
                if(tmp_zetanize!={}):
                    for i in tmp_zetanize:
                        if(i['method'].lower()=='post'):
                            zetanize_lists.append([posturl.rstrip(),{0:i}])
            except:
                print('error on '+posturl)
                time.sleep(2)
                continue

        taskflag+=1
        #end zetanize
        print(zetanize_lists)
        vuln_list=[]
        #little_task=taskcal/len(get_lists)
        get_count=0
        #GeT attack (dynamic URL)
        for get_list in get_lists:
            print("--------------------------")
            print(get_list)

            #ci attack
            ci_result=ci_attack(get_list[0],get_list[1],cookies)
            if(ci_result!=None and ci_result!=False):
                vuln_list.append(ci_result)
            taskflag+=1
            current_task.update_state(state='PROGRESS',meta={'process_percent': taskflag*taskcal})

            #xss_attack
            xss_result=xss_attack(get_list[0],get_list[1],cookies)
            if(xss_result!=None and xss_result!=False):
                vuln_list.append(xss_result)
            taskflag+=1
            current_task.update_state(state='PROGRESS',meta={'process_percent': taskflag*taskcal})
            #lfi_attack
            lfi_result=lfi_attack(get_list[0],get_list[1],cookies)
            if(lfi_result!=None and lfi_result!=False):
                vuln_list.append(lfi_result)
            taskflag+=1
            current_task.update_state(state='PROGRESS',meta={'process_percent': taskflag*taskcal})

            #rfi_attack
            rfi_result=rfi_attack(get_list[0],get_list[1],cookies)
            if(rfi_result!=None and rfi_result!=False):
                vuln_list.append(rfi_result)
            taskflag+=1
            current_task.update_state(state='PROGRESS',meta={'process_percent': taskflag*taskcal})
            
            #sqli_attack
            sqli_result=sqli_attack(get_list[0],get_list[1],cookies)
            if(sqli_result!=None and sqli_result!=False):
                vuln_list.append(sqli_result)
            taskflag+=1
            current_task.update_state(state='PROGRESS',meta={'process_percent': taskflag*taskcal})
            print(vuln_list)

        for post_list in zetanize_lists:
            print("---------post-------------")
            print(post_list)
            #ci attack
            ci_result=ci_attack(post_list[0],post_list[1],cookies)
            if(ci_result!=None and ci_result!=False):
                vuln_list.append(ci_result)
            taskflag+=1
            current_task.update_state(state='PROGRESS',meta={'process_percent': taskflag*taskcal})

            #lfi_attack
            lfi_result=lfi_attack(post_list[0],post_list[1],cookies)
            if(lfi_result!=None and lfi_result!=False):
                vuln_list.append(lfi_result)
            taskflag+=1
            current_task.update_state(state='PROGRESS',meta={'process_percent': taskflag*taskcal})

            #xss_attack
            xss_result=xss_attack(post_list[0],post_list[1],cookies)
            if(xss_result!=None and xss_result!=False):
                vuln_list.append(xss_result)
            taskflag+=1
            current_task.update_state(state='PROGRESS',meta={'process_percent': taskflag*taskcal})

            #rfi_attack
            rfi_result=rfi_attack(post_list[0],post_list[1],cookies)
            if(rfi_result!=None and rfi_result!=False):
                vuln_list.append(rfi_result)
            taskflag+=1
            current_task.update_state(state='PROGRESS',meta={'process_percent': taskflag*taskcal})
            
            #sqli_attack
            sqli_result=sqli_attack(post_list[0],post_list[1],cookies)
            if(sqli_result!=None and sqli_result!=False):
                vuln_list.append(sqli_result)
            taskflag+=1
            current_task.update_state(state='PROGRESS',meta={'process_percent': taskflag*taskcal})
            print(vuln_list)

        #vuln_list.append(rfi_attack('http://192.168.112.130/vulnerabilities/fi/?page=include.php'))
        with open(current_path + '/detectedVuln/'+str(new_id)+'.json', 'r') as infile:
            result_data = json.load(infile)
        print(vuln_list)
        for vuln_element in vuln_list:
            if vuln_element != [] :
                if( vuln_element['vuln'] not in result_data.keys() ):
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

        with open(current_path + '/detectedVuln/'+str(new_id)+'.json', 'w') as outfile:
            json.dump(result_data, outfile, indent=4)
        

    current_task.update_state(state='PROGRESS',meta={'process_percent': 100})
    return True