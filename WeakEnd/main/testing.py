import base64
import os, sys, urllib, re, string
from ssl import SSLError
from urllib.error import HTTPError

import requests
from urllib import parse
from urllib.parse import urlparse


def zetanize(response):  ####form parser
    def e(string):
        return string.encode('utf-8')

    def d(string):
        return string.decode('utf-8')

    response = re.sub(r'(?s)<!--.*?-->', '', response)
    forms = {}
    matches = re.findall(r'(?i)(?s)<form.*?</form.*?>', response)
    num = 0
    for match in matches:
        page = re.search(r'(?i)action=[\'"](.*?)[\'"]', match)
        method = re.search(r'(?i)method=[\'"](.*?)[\'"]', match)
        forms[num] = {}
        forms[num]['action'] = d(e(page.group(1))) if page else ''
        forms[num]['method'] = d(e(method.group(1)).lower()) if method else 'get'
        forms[num]['inputs'] = []
        if(forms[num]['method']==''):forms[num]['method']='get'
        inputs = re.findall(r'(?i)(?s)<input.*?>', match)
        for inp in inputs:
            inpName = re.search(r'(?i)name=[\'"](.*?)[\'"]', inp)
            if inpName:
                inpType = re.search(r'(?i)type=[\'"](.*?)[\'"]', inp)
                inpValue = re.search(r'(?i)value=[\'"](.*?)[\'"]', inp)
                inpName = d(e(inpName.group(1)))
                inpType = d(e(inpType.group(1)) )if inpType else ''
                inpValue = d(e(inpValue.group(1))) if inpValue else ''
                if inpType.lower() == 'submit' and inpValue == '':
                    inpValue = 'Submit Query'
                inpDict = {
                'name' : inpName,
                'type' : inpType,
                'value' : inpValue
                }
                forms[num]['inputs'].append(inpDict)
        num += 1
    return forms


cookies = {'PHPSESSID': '6ur3g995en5ocvhhpa53lbf0g2', 'security': 'low'}
url='192.168.112.130_80'
with open(os.path.dirname(os.path.realpath(__file__)) + '/vuln_detect/vuln_code/dirscanning/'+url+'/'+url+'-dynamic-unique.txt', 'r') as f:
    geturls=f.readlines()

get_list=[]
for geturl in geturls:
    get_list.append(["get",geturl.rstrip()])
print(get_list)

with open(os.path.dirname(os.path.realpath(__file__)) + '/vuln_detect/vuln_code/dirscanning/'+url+'/'+url+'-forms-sorted.txt', 'r') as f:
    posturls=f.readlines()
print()
print()
zetanize_list=[]
for posturl in posturls:
    res = requests.get(posturl.rstrip(),cookies=cookies,verify=False)
    tmp_zetanize=list(zetanize(res.text).values())
    if(tmp_zetanize!={}):
        for i in tmp_zetanize:
            if(i['method'].lower()=='post'):
                zetanize_list.append([posturl.rstrip(),{0:i}])
print(zetanize_list)
