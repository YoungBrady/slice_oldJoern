import pickle
import os
import shutil
import re
import sys


def get_cwe_file(src_path,old_path, new_path, cwe_list):
    i=0
    for software in os.listdir(src_path):
        for cve_id in os.listdir(os.path.join(src_path, software)):
            for filename in os.listdir(os.path.join(src_path, software, cve_id)):
                if filename.endswith("OLD.c") and filename.split('_')[1] in cwe_list:
                    new_filename = f"{filename[:-5]}NEW.c"
                    if not os.path.exists(os.path.join(src_path, software, cve_id, new_filename)): #只有OLD没有NEW文件不提取
                        continue

                    old_file_path=os.path.join(old_path, software, cve_id)
                    if not os.path.exists(old_file_path):
                        os.makedirs(old_file_path)
                    src1 = os.path.join(src_path, software, cve_id, filename)
                    des1 = os.path.join(old_file_path, filename)
                    ret=shutil.copyfile(src1, des1)

                    new_file_path=os.path.join(new_path, software, cve_id)
                    if not os.path.exists(new_file_path):
                        os.makedirs(new_file_path)
                    src2 = os.path.join(src_path, software, cve_id, new_filename)
                    des2 = os.path.join(new_file_path, new_filename)
                    shutil.copyfile(src2, des2)
                    i+=1
    return i

def make_software_consistent(_path1, _path2):
    software1=os.listdir(_path1)
    software2=os.listdir(_path2)

    for software in software1:
        if software not in software2:
            print('new', software)
            shutil.rmtree(os.path.join(_path1, software))

    for software in software2:
        if software not in software1:
            print('old', software)
            shutil.rmtree(os.path.join(_path2, software))      


def make_cve_consistent(_path1, _path2):
    for software in os.listdir(_path1):
        cve1 = os.listdir(os.path.join(_path1, software))
        cve2 = os.listdir(os.path.join(_path2, software))
        for cve_id in cve1:
            if cve_id not in cve2:
                print('new', cve_id)
                shutil.rmtree(os.path.join(_path1, software, cve_id))
        for cve_id in cve2:
            if cve_id not in cve1:
                print('old', cve_id)
                shutil.rmtree(os.path.join(_path2, software, cve_id))


def make_file_consistent(_path1, _path2):
    rmlist = []
    for software in os.listdir(_path1):
        for cve_id in os.listdir(os.path.join(_path1, software)):
            for filename in os.listdir(os.path.join(_path1, software, cve_id)):
                if 'OLD' in filename:
                    if not os.path.exists(os.path.join(_path2, software, cve_id, filename.replace('OLD', 'NEW'))):
                        rmlist.append(os.path.join(_path1, software, cve_id, filename))
                elif 'NEW' in filename:
                    if not os.path.exists(os.path.join(_path2, software, cve_id, filename.replace('NEW', 'OLD'))):
                        rmlist.append(os.path.join(_path1, software, cve_id, filename))
    print(rmlist)
    for files in rmlist:
        os.remove(files)


def process_diff(code_path, diff_path, dest_path):
    """
    It takes a diff file, and a code file, and produces a new code file with the diff applied
    
    :param code_path: the path to the codebase
    :param diff_path: the path to the diff file
    :param dest_path: The path to the directory where the output files will be stored
    """
    i=0
    for software in os.listdir(code_path):
        for cve_id in os.listdir(os.path.join(code_path, software)):
            for filename in os.listdir(os.path.join(code_path, software, cve_id)):
                for diffname in os.listdir(os.path.join(diff_path, software, cve_id)):
                    if diffname[:-5] in filename:
                        filepath = os.path.join(dest_path, software, cve_id)
                        if(not os.path.exists(filepath)):
                            os.makedirs(filepath)
                        src = os.path.join(diff_path, software, cve_id, diffname)
                        des = os.path.join(dest_path, software, cve_id, diffname)
                        # print(des)
                        shutil.copyfile(src, des)
                        i+=1
                        break
    print(i)

def get_diff_linedict(diff_path):  # sourcery skip: low-code-quality
    new_dict={}
    old_dict={}
    linenum_dict={}
    begin_dict={'old':{},'new':{}}
    linenum_sub=0
    linenum_add=0
    # blank_linenum=0
    # linenum=0

    for software in os.listdir(diff_path):

        for cve_id in os.listdir(os.path.join(diff_path, software)):
            for filename in os.listdir(os.path.join(diff_path, software, cve_id)):
                fileid=('.').join(filename.split('.')[:-2])

                if fileid not in old_dict:
                    old_dict[fileid]=set()
                else:
                    print('dup')
                if fileid not in new_dict:
                    new_dict[fileid]=set()
                else:
                    print('dup')
                if fileid not in begin_dict['old']:
                    begin_dict['old'][fileid]=set()
                else:
                    print('dup')
                if fileid not in begin_dict['new']:
                    begin_dict['new'][fileid]=set()
                else:
                    print('dup')
                with open(os.path.join(diff_path, software, cve_id,filename),'r') as f:
                    sentences=f.readlines()
                i=0
                while (i<len(sentences)):
                    if len(sentences[i])>2 and sentences[i][:2]=='@@':
                        ret=re.findall(r'@@ -([0-9]+),([0-9]+) \+([0-9]+),([0-9])+ @@',sentences[i])
                        if ret==[]:
                            continue
                        linenum_sub,_,linenum_add,_=ret[0]
                        begin_dict['old'][fileid].add(linenum_sub)
                        begin_dict['new'][fileid].add(linenum_add)
                        linenum_add = int(linenum_add) + 2
                        linenum_sub = int(linenum_sub) + 2
                        i+=3 #跳过本行及hunk开头的空白行
                    elif len(sentences[i]) > 2 and sentences[i][:2] in ['- ', '-\t']:
                        linenum_sub+=1
                        old_dict[fileid].add(linenum_sub)
                    elif len(sentences[i]) > 2 and sentences[i][:2] in ['+ ', '+\t']:
                        linenum_add+=1
                        new_dict[fileid].add(linenum_add)
                    else:
                        linenum_add+=1
                        linenum_sub+=1

                    i+=1
    linenum_dict['old']=old_dict
    linenum_dict['new']=new_dict
    # print(old_dict['CVE-2018-10878_CWE-787_819b23f1c501b17b9694325471789e6b5cc2d0d2_balloc.c_4'])
    # print(new_dict['CVE-2018-10878_CWE-787_819b23f1c501b17b9694325471789e6b5cc2d0d2_balloc.c_4'])
    return linenum_dict,begin_dict


                        



def main():
    cwe = 119
    # cwe = sys.argv[1]
    cwe = f'CWE-{cwe}'
    root_dir='/home/wanghu/slice_data/NVD'
    src_path = os.path.join(root_dir,'NVD_file/')
    diff_path = os.path.join(root_dir,'NVD_diff/')
    # new_path = './CWE-119_new/'
    # old_path = './CWE-119_old/'
    # cwe_diff = './CWE-119_diff/'
    new_path = os.path.join(root_dir,f'{cwe}/new/')
    old_path = os.path.join(root_dir,f'{cwe}/old/')
    cwe_diff = os.path.join(root_dir,f'{cwe}/diff/')
    # cwe_list = ['CWE-120', 'CWE-125', 'CWE-466',
    # 'CWE-680','CWE-786','CWE-787','CWE-788',
    # 'CWE-805','CWE-822','CWE-823','CWE-824','CWE-825']
    # cwe_list = ['CWE-120', 'CWE-125', 'CWE-466',
    # 'CWE-680','CWE-786','CWE-787','CWE-788',
    # 'CWE-805','CWE-822','CWE-823','CWE-824','CWE-825']

    cwe_list_dict={
        'CWE-119':['CWE-119','CWE-120','CWE-121','CWE-122', 'CWE-125', 'CWE-787'],
        'CWE-20':['CWE-20','CWE-179','CWE-622','CWE-1173','CWE-1284','CWE-1285','CWE-1286','CWE-1287','CWE-1288','CWE-1289'],
        'CWE-189':['CWE-189'],
        'CWE-200':['CWE-200','CWE-201','CWE-203','CWE-209','CWE-213','CWE-215','CWE-359','CWE-497','CWE-538','CWE-1258','CWE-1273','CWE-1295',],
        'CWE-264':['CWE-264'],
        'CWE-362':['CWE-362','CWE-364','CWE-366','CWE-367','CWE-368','CWE-421','CWE-689','CWE-1223','CWE-1298'],
        'CWE-399':['CWE-399'],
        'CWE-416':['CWE-416'],
        'CWE-476':['CWE-476','CWE-690']
    }
    cwe_list=cwe_list_dict[cwe]
    # ret=get_cwe_file(src_path,old_path,new_path,cwe_list)
    # print(ret)
    # make_software_consistent(old_path, new_path)
    # make_cve_consistent(old_path, new_path)
    # make_file_consistent(old_path, new_path)
    # make_file_consistent(new_path, old_path)
    # process_diff(old_path, diff_path, cwe_diff)
    linenum_dict,begin_dict=get_diff_linedict(cwe_diff)
    with open(os.path.join(root_dir, f'{cwe}/{cwe}_linenum_dict.pkl'),'wb') as f:
        pickle.dump(linenum_dict,f,protocol=2)
    with open(os.path.join(root_dir, f'{cwe}/{cwe}_begin_dict.pkl'),'wb') as f:
        pickle.dump(begin_dict,f,protocol=2)


if __name__ == '__main__':
    main()
    # old_dict,new_dict=get_diff_linedict('./CWE-119_diff/')
    # f=open('cwe-119_old.pkl','wb')
    # pickle.dump(old_dict,f)
    # f.close()
    # f=open('cwe-119_new.pkl','wb')
    # pickle.dump(new_dict,f)
    # f.close()
    # for fileid in old_dict:
    #     print('old',fileid,old_dict[fileid])
    # for fileid in new_dict:
    #     print('new',fileid,new_dict[fileid])