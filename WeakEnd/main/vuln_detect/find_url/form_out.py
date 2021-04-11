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
    print(matches)
    print()
    print()
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

res = requests.get("https://nid.naver.com/nidlogin.login?mode=form&url=https%3A%2F%2Fwww.naver.com",verify=False)
a=zetanize(res.text)
print(a)
'''
def check_url(url):
    res = requests.get(url)
    #Valid
    if res.status_code == 200:
        return True
    else:
        #InValid
        return False

def check_form:
    url= 'https://ajou.ac.kr/kr/index.do' # 웹페이지에서 입력받은 url
    complete_url(url)
    if check_url(url) == True:
        parts=list(url.split('/'))
        domain = parts[2]
        #print(domain)
        main_get = '/usr/share/blackwidow/' + domain +'_80/' + domain +'_80'+'-dynamic-sorted.txt'
        sublist_path = '/usr/share/blackwidow/' + domain +'_80/' + domain +'_80'+'-subdomains-sorted.txt'
        subdomain_list = []
        get_list = []
        ### subdomain_list###------------
        sublist_txt = open(sublist_path , "r")
        while True:
            subdomain = sublist_txt.readline().rstrip('\n')
            if not subdomain:
                break
            subdomain_list.append(subdomain)
        sublist_txt.close()
        
        ###maindomain_url_for_POST### ----------------
        main_url = '/usr/share/blackwidow/' + domain +'_80/' + domain +'_80'+'-urls-sorted.txt'
        main_url2 = '/usr/share/blackwidow/' + domain + '_80/' + domain + '_80' + '-forms-sorted.txt'
        main_url_txt= open(main_url,"r")
        url_list=[]
        while True:
            main_url = main_url_txt.readline().rstrip('\n')
            if not main_url:
                break
            url_list.append(main_url)
        main_url2_txt = open(main_url2, "r")
        while True:
            main_url2 = main_url2_txt.readline().rstrip('\n')
            if not main_url2:
                break
            url_list.append(main_url2)

        ###subdomain_url_for_POST### ----------------
        for i in range(len(subdomain_list)):
            try:
                subdomain_url_path= '/usr/share/blackwidow/' + domain +'_80/' + subdomain_list[i] +'_80'+'-urls.txt'
                subdomain_url_txt= open(subdomain_url_path, "r")
                while True:
                    url = subdomain_url_txt.readline().rstrip('\n')
                    if not url:
                        break
                    url_list.append(url)
                subdomain_url_txt.close()
            except: FileNotFoundError
        ###scan_start###------------------------------------
        print("scan_start")

        for url in url_list:
            try:
                print(url)
                res = requests.get(url, verify=False)
                form = zetanize(res.text)
                print(form)
                for i in range(len(form)):
                    if form[i]['method'] == 'post':  ###get form 걸러진다
                        #LFI_POST(form)
                        scan_rfi_post(url,form[i])
                        #command_Injection_POST(form)
            except HTTPError as e:
                print(e)
            except SSLError as e:
                print(e)
            except ConnectionError as e:
                print(e)
    else: #invalid url
        print('')
'''