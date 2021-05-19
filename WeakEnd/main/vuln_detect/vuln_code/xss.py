import requests
import os
import re

cookies = {'PHPSESSID': 'cnav05h5ltgj1f5eqaorvq01v2', 'security': 'low'}


def make_GET_form(url: str):
    dic = {}
    dic['vuln'] = ' XSS'
    dic['method'] = 'GET'
    dic['url'] = url
    return dic


def make_POST_form(url: str, data: dict):
    dic = {}
    dic['vuln'] = 'XSS'
    dic['method'] = 'POST'
    dic['url'] = url
    dic['data'] = data
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
            final_form = middle_form.replace('@@@@@@', payload.strip())
            test_res = requests.get(final_form, cookies=cookies)
            if check_success(test_res.text, payload.strip()):
                return make_GET_form(final_form)
    return False


def scan_type1(url: str, params: dict):
    global cookies
    with open(os.path.dirname(os.path.realpath(__file__)) + '/xss.txt', "r") as f:
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
                    tmp[payload_name] = payload.strip()
                    test_res = requests.post(target, data=tmp, cookies=cookies)
                    if check_success(test_res.text, payload.strip()):
                        return make_POST_form(target, tmp)
        elif method == 'get':
            return get_request(data, dic, target)
        else:
            print('Error in ' + target + ', method type must be assigned')
            return False
    return False


def scan_type2(url: str):
    with open(os.path.dirname(os.path.realpath(__file__)) + '/xss.txt', "r") as f:
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

    return get_request(data, dic, target)


def check_success(res, payload):
    # 페이로드에 알람 코드가 존재하면 탐지 성공
    if re.search(r'<.*alert.*(1 | XSS).*>', res):
        return True
    # 응답으로 온 코드에 사용한 페이로드가 그대로 존재하면 탐지 성공 반환
    if payload in res:
        return True
    # 응답으로 온 코드에 사용한 페이로드가 없으면 실패 반환
    return False


def xss_attack(arg1: str, arg2):
    # arg1이 URL, arg2가 사전형 파라미터인 경우 탐지 수행 및 결과 반환
    if arg1.startswith('http'):
        return scan_type1(arg1, arg2)
    # arg1이 get 문자열, arg2가 전체 타겟 URL인 경우 탐지 수행 및 결과 반환
    elif arg1 == 'get':
        return scan_type2(arg2)
    # 취약점 탐지 실패
    else:
        print('Error in xss_attack')
        return False