"""
记录一些匹配漏洞sink点类型所需要的函数，这些函数可能被不同的sink点类型调用到

"""
import pickle
from get_tokens import create_tokens

sp_operators = ['+', '-', '/', '*', '%', '&', '|', '=']

def has_only_cv(line, cv):
    if (cv + ' ->') in line:  # cv = s, line : bs -> opaque
        lines = line.split(" ")
        # index = lines.index('->')
        # if cv == lines[index - 1]:
        if cv in lines:
            return False
    if (cv + ' .') in line:
        return False
    return has_cv(cv, line)

def has_cv(cv, line):
    # print(('*' + cv + ','))

    if ((' ' + cv + ',') in line):
        return True
    if ((' ' + cv + ';') in line):
        return True
    if ((' ' + cv + ')') in line):
        return True
    if ((' ' + cv + ' ,') in line):
        return True
    if ((' ' + cv + ' ;') in line):
        return True
    if ((' ' + cv + ' )') in line):
        return True
    if (('*' + cv + ';') in line):
        return True
    if ((' ' + cv + ' ') in line):
        return True
    if ((' ' + cv + '[') in line):
        return True
    if (('*' + cv + ',') in line):
        return True
    if (('*' + cv + ')') in line):
        return True
    if (cv + ' =') in line:
        return True
    if (cv + ' +') in line:
        return True
    if (cv + ' -') in line:
        return True

    return False

def is_risk_func(line, cv):
    # print('this is a test.')
    if not has_cv(cv, line):  # ar -> gpe . en = g_malloc0 ( len / 2 ); 避免这种情况匹配不到
        return False
    if ('memcpy' in line):  # 之后换成正则表达式应该会更好
        return True
    elif ('alloc' in line):
        if "=" in line:
            if "alloc" in line.split('=')[-1]:
                return True
        else:
            return True
    elif ('memset' in line):
        return True
    elif 'strncpy' in line:
        return True
    elif 'strcmp' in line:
        return True
    elif('RTL_W16' in line):
        return True
    elif ('bytestream2_get_buffer' in line):
        return True
    elif ('get_bits' in line):
        return True
    elif ('put_bits' in line) or 'skb_put' in line:
        return True
    elif ('copy' in line) and 'copy_size' not in line:
        return True
    elif ('recv' in line and 'recv ->' not in line):
        return True
    elif ('Write' in line or 'write' in line): #and '_write' not in line:
        return True
    elif 'read' in line or 'Read' in line:
        return True
    elif 'EXTRACT' in line:  # 针对tcpdump软件的EXTRACT_32BITS宏定义访问指针
        return True
    elif 'TT_NEXT_U' in line: #针对freetype2软件中的TT_NEXT_ULONG/INT(...)宏定义
        return True
    else:
        return False

def is_risk_func_1(line, cv):
    list_tokens = create_tokens(line)
    if cv not in list_tokens:  # ar -> gpe . en = g_malloc0 ( len / 2 ); 避免这种情况匹配不到
        return False
    f = open("./sensitive_func.pkl", 'rb')
    list_sensitive_funcname = pickle.load(f)
    f.close()
    for func_name in list_sensitive_funcname:
        if func_name in line:
            return True
    return False


def is_pointer(line, cv, point_var):  # 需要更新切片文件才能测试,可暂定
    if (cv in point_var):
        # 变量是指针且参与运算
        if (is_calculation(line, cv)):
            return True
        # print()
    sp_type = ''
    if (('* ' + cv + ' ') in line):
        sp_type = '* ' + cv + ' '
    elif (('*' + cv + ' ') in line):
        sp_type = '*' + cv + ' '
    elif (line[-len('* ' + cv):] == ('* ' + cv)):
        sp_type = '* ' + cv
    elif (line[-len('*' + cv):] == ('*' + cv)):
        sp_type = '*' + cv

    if (sp_type == ''):
        return False

    sp_res = line.split(sp_type)
    sp_var = sp_res[0].strip()
    if (sp_var != ''):
        sp_var = sp_var[-1]
    if (sp_var in sp_operators):  # 关键变量前面是运算符，说明这里的*不是用作乘号
        return True
    else:
        return False


# 关键变量为数组下标或者作为数组的使用
def is_array(line, cv):
    # ptr += s -> frame -> linesize [ 0 ] 不算数组访问越界吧
    if (cv + ' [ 0 ]') in line:
        return False
    if cv + '[%d]' in line:  # n_entries[%d]不是访问
        return False
    if '[ 0 ]' in line:
        line = line.replace('[ 0 ]', '')
        if '[' and ']' not in line:
            return False

    # 其实关键变量只要在[]里面就算是在数组下标里了,可能和其他值一起参与了计算,例如dst[y+len]这样
    lbracket = line.find('[')
    rbracket = line.rfind(']')
    cv_loc = line.find(' ' + cv + ' ')
    if ((cv_loc > lbracket) and (cv_loc < rbracket)):
        return True
    '''
    if(('[' + cv + ']') in line):#作为数组下标
        #print('1')
        return True
    elif(('[ ' + cv + ' ]') in line):#作为数组下标
        #print('2')
        return True
    '''
    if ((' ' + cv + ' [') in line):  # 作为数组
        # print('3')
        return True
    if ((' ' + cv + '[') in line):
        # print('4')
        return True
    if (line[:len(cv)] == cv):  # 关键变量在一行的开始处
        if (line[:(len(cv) + 2)] == cv + ' ['):
            return True
        if (line[:(len(cv) + 1)] == cv + '['):
            return True
    return False


#  sink点是整数运算导致的整数溢出类型匹配
def is_calculation(line, cv):
    if '(' in line and ')' in line:  # 在函数参数或者if，while条件中，整数溢出不需要等号
        tmps = line[line.find('('):line.find(')') - 1]
        if ',' in tmps:
            tmps = tmps.split(',')
            for tmp in tmps:
                if (cv + ' *') in tmp or (cv + ' +') in tmp or ('* ' + cv) in tmp or ('+ ' + cv) in tmp:
                    return True
    if (cv + ' *') in line and '=' in line:  # 要有等号才算是整数溢出吗？
        return True
    if ('* ' + cv) in line and '=' in line:
        if '*' == line[0]:
            return False
        return True
    if (cv + ' +') in line or ('+ ' + cv) in line:
        return True
    if (cv + '+=') in line:
        return True
    if (cv + ' -') in line and (cv + ' ->') not in line:
        return True
    if ('- ' + cv) in line:
        return True
    if (cv + ' =') in line and '+' in line:
        return True
    return False
