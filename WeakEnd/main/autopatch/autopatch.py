import re
import os

class Patch:
    def __init__(self):
        self.func = ''
        self.reg = ''
        self.reg_list = []
        self.reg_some_var = ''
        self.patch_type = ''
        self.some_var = ''
        self.describ = ''
        self.lists = []

    def set_func(self, func: str):
        self.func = func

    def set_reg(self, reg: str):
        self.reg = reg

    def set_reg_list(self, reg_dic: list):
        self.reg_list.append(reg_dic)

    def set_patch_type(self, patch_type: str):
        self.patch_type = patch_type

    def set_patch_describ(self, describ: str):
        self.describ = describ.strip()

    def set_reg_some_var(self):
        for reg in self.reg_list:
            if reg[1] != 'some_var':
                continue
            self.reg_some_var = reg[0]
            return

    def set_list(self, lists: list):
        self.lists = lists

    def find_reg_type(self, data: str):
        for reg in self.reg_list:
            if reg[1] != 'func_decr_name' and reg[1] != 'func_name' and reg[1] != 'func_var_name' and reg[1] != 'simple_sub' and reg[1] != 'func_name_end' and reg[1] != 'func_list2':
                continue
            match = re.search(reg[0], data)
            if match is None:
                continue
            self.set_reg(reg[0])
            self.set_patch_type(reg[1])
            break

    def find_some_var(self, data: str):
        if self.reg_some_var == '':
            return
        match = re.search(self.reg_some_var, data)
        self.some_var = match.group(1)


def distinguish_lang(language) -> str:
    # Assume that the language used has already been entered.
    if int(language) == 0:
        used_lang = 'PHP'
    elif int(language) == 1:
        used_lang = 'ASP.NET'
    elif int(language) == 2:
        used_lang = 'Java'
    elif int(language) == 3:
        used_lang = 'Python'
    elif int(language) == 4:
        used_lang = 'JavaScript'
    else:
        used_lang = 'Perl'

    return used_lang


def get_vuln_type(vulnerability) -> str:
    if int(vulnerability) == 0:
        vuln_name = 'SQL Injection'
    elif int(vulnerability) == 1:
        vuln_name = 'XSS'
    elif int(vulnerability) == 2:
        vuln_name = 'File Inclusion'
    else:
        vuln_name = 'Command Injection'
    return vuln_name

def get_patch_info(lang: str, vuln_type: str) -> Patch:
    with open( os.path.dirname(os.path.realpath(__file__)) + '/vulnList/' + vuln_type + "-" + lang + ".txt", 'r') as f:
        lines = f.readlines()

    text_type = ''
    vuln = Patch()
    tmp_str = ''
    params = []

    for line in lines:
        if line[:10] == '%%%%%%%%%%' and text_type == '':
            text_type = line[10:14]
        elif line[:10] == '%%%%%%%%%%' and text_type == 'FUNC':
            vuln.set_func(tmp_str)
            text_type = ''
            tmp_str = ''
        elif line[:10] == '%%%%%%%%%%' and text_type == 'REGE':
            text_type = ''
            tmp_str = ''
            params = []
        elif line[:10] == '%%%%%%%%%%' and text_type == 'PRNT':
            vuln.set_patch_describ(tmp_str)
            text_type = ''
            tmp_str = ''
        elif line[:10] == '%%%%%%%%%%' and text_type == 'LIST':
            text_type = ''
            tmp_str = ''
            vuln.set_list(params)
            params = []
        elif text_type == 'REGE':
            params = line.split('%')
            vuln.set_reg_list([params[0].strip(), params[1].strip()])
        elif text_type == 'LIST':
            line = line.strip()
            params.append(line)
        else:
            tmp_str = tmp_str + line

    return vuln


def insert_func(code: str, func: str) -> str:
    index = code.find('\n')
    return code[:index] + '\n' + func + code[index:]


def patch_list2_type(code: str, reg: str, lists: list):
    matches = re.finditer(reg, code)
    offset = 0
    for match in matches:
        start_index = match.start() + offset
        end_index = match.end() + offset
        before_len = end_index - start_index
        input_start = start_index + code[start_index:end_index].find(match.group(2))
        input_end = input_start + len(match.group(2))
        patched = lists[0] + match.group(2) + lists[1]
        after_len = before_len + len(patched) - len(match.group(2))
        offset = offset + after_len - before_len
        code = code[:input_start] + patched + code[input_end:]
    return code


def patch_func_var_name_type(code: str, reg: str, func_name: str, some_var: str):
    matches = re.finditer(reg, code)
    offset = 0
    for match in matches:
        start_index = match.start() + offset
        end_index = match.end() + offset
        before_len = end_index - start_index
        input_start = start_index + code[start_index:end_index].find(match.group(2))
        input_end = input_start + len(match.group(2))
        patched = func_name + some_var + ', ' + match.group(2) + ')'
        after_len = before_len + len(patched) - len(match.group(2))
        offset = offset + after_len - before_len
        code = code[:input_start] + patched + code[input_end:]
    return code


def patch_simple_sub_type(code: str, reg: str, lists: list):
    matches = re.finditer(reg, code)
    offset = 0
    for match in matches:
        start_index = match.start() + offset
        end_index = match.end() + offset
        before_len = end_index - start_index
        patched = code[start_index:end_index].replace(match.group(1), lists[0])
        after_len = before_len + len(lists[0]) - len(match.group(1))
        offset = offset + after_len - before_len
        code = code[:start_index] + patched + code[end_index:]
    return code


def vulnerability_patch(language,vulnerability,data):


    lang = distinguish_lang(language)
    vuln_type = get_vuln_type(vulnerability)
    vuln_patch_info = get_patch_info(lang, vuln_type)
    vuln_patch_info.find_reg_type(data)
    vuln_patch_info.set_reg_some_var()
    vuln_patch_info.find_some_var(data)
    func_inserted = insert_func(data, vuln_patch_info.func)

    '''if vuln_patch_info.patch_type == 'func_var_name':
        result = patch_func_var_name_type(func_inserted, vuln_patch_info.reg, vuln_patch_info.func_name, vuln_patch_info.some_var)'''

    if vuln_patch_info.patch_type == 'simple_sub':
        result = patch_simple_sub_type(func_inserted, vuln_patch_info.reg, vuln_patch_info.lists)
    elif vuln_patch_info.patch_type == 'func_list2':
        result = patch_list2_type(func_inserted, vuln_patch_info.reg, vuln_patch_info.lists)
    else:
        result = vuln_patch_info.describ
    return result

