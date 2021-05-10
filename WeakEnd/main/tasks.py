from __future__ import absolute_import, unicode_literals
from celery import shared_task,current_task
from celery import Celery
from .vuln_detect.vuln_code.ci import ci_attack
from .vuln_detect.vuln_code.lfi import lfi_attack
from .vuln_detect.vuln_code.rfi import rfi_attack
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
def checkvuln(url,cookie,level,new_id):
    current_task.update_state(state='PROGRESS',meta={'process_percent': 0})
    result_data={}


    # zetanize + making input
    cookies = {'PHPSESSID': 'n5p04ib16hs5q9o14bsdrutnr7', 'security': 'low'}
    url='192.168.112.130_80'
    with open(os.path.dirname(os.path.realpath(__file__)) + '/vuln_detect/vuln_code/dirscanning/'+url+'/'+url+'-dynamic-unique.txt', 'r') as f:
        geturls=f.readlines()

    get_lists=[]
    for geturl in geturls:
        get_lists.append(["get",geturl.rstrip()])
    print(get_lists)

    with open(os.path.dirname(os.path.realpath(__file__)) + '/vuln_detect/vuln_code/dirscanning/'+url+'/'+url+'-forms-sorted.txt', 'r') as f:
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
    #end zetanize
    print(zetanize_lists)

    vuln_list=[]
    for get_list in get_lists:
        print("-------------------------")
        print(get_list)
        ci_result=ci_attack(get_list[0],get_list[1])
        if(ci_result!=None and ci_result!=False):
            vuln_list.append(ci_result)

        lfi_result=lfi_attack(get_list[0],get_list[1])
        if(lfi_result!=None and lfi_result!=False):
            vuln_list.append(lfi_result)
    
    for post_list in zetanize_lists:
        print("-------------------------")
        print(post_list)
        ci_result=ci_attack(post_list[0],post_list[1])
        if(ci_result!=None and ci_result!=False):
            vuln_list.append(ci_result)

        lfi_result=lfi_attack(post_list[0],post_list[1])
        if(lfi_result!=None and lfi_result!=False):
            vuln_list.append(lfi_result)

    #vuln_list.append(rfi_attack('http://192.168.112.130/vulnerabilities/fi/?page=include.php'))

    print(vuln_list)

    for vuln_element in vuln_list:
        if vuln_element != [] :
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
