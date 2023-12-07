# -*- coding:utf-8 -*-
import pickle
import os
import random
import hashlib
import multiprocessing
# from mapping import *
# import tqdm
# from gensim.models.word2vec import Word2Vec
import pickle
import os
import datetime
import igraph as ig
from cmath import inf
# from attr import validate

slice_all_len=0
def get_codes_labels_and_edges(path, old_dict, new_dict, type):
    global slice_all_len
    slicedir = os.path.join(path, 'slice_source')
    edgesdir = os.path.join(path, 'edges_source')
    focus_list = ['api', 'array', 'integer_overflow', 'pointer']
    code_label_edges = []
    # filepath2sample={}
    if type == 'old':
        label_dict = old_dict
    else:
        label_dict = new_dict
    for focus in focus_list:
        slice_file = os.path.join(slicedir, focus+'_slices.txt')
        edge_file = os.path.join(edgesdir, focus+'_edges.txt')

        # print(slice_file,edge_file)
        if not os.path.exists(slice_file):
            continue
        if not os.path.exists(edge_file):
            continue
        f = open(slice_file, "r")
        slicelists = f.read().split('------------------------------\n')
        f.close()
        f = open(edge_file, "r")
        edgelists = f.read().split('------------------------------\n')
        f.close()
        # print(slicelists)
        if slicelists == ['']:
            continue
        if edgelists == ['']:
            continue
        if slicelists[0] == '':
            del slicelists[0]
        if slicelists[-1] == '' or slicelists[-1] == '\n' or slicelists[-1] == '\r\n':
            del slicelists[-1]
        if edgelists[0] == '':
            del edgelists[0]
        if edgelists[-1] == '' or edgelists[-1] == '\n' or edgelists[-1] == '\r\n':
            del edgelists[-1]

        index = -1
        for slices in slicelists:
            empty_line=False

            index += 1
            # print('slice',slices)
            if slices == '':
                continue
            sentences = slices.split('\n')
            # print(sentence)
            if sentences[0] == '\r' or sentences[0] == '':
                del sentences[0]
            if sentences[-1] == '' or sentences[-1] == '\r':
                del sentences[-1]
            if sentences == []:
                continue

            # print('sentence0',sentences[0])
            if 'location:'in sentences[0] or 'file:'in sentences[0]:
                slice_all_len+=1
                continue
            filepath=sentences[0].split(' @@ ')[1].strip()
            fileID = filepath.split('/')[-1][:-8]
            cve=filepath.split('/')[-3]
            # silcename_list=sentences[0].split(' @@ ')
            funcname=sentences[0].split(' @@ ')[2].strip()
            slicename=fileID+funcname
            # slicename=silcename_list[1]+silcename_list[2]+silcename_list[4]
            # slicename=silcename_list[1].strip()+silcename_list[2].strip()
            cwe=filepath.split('/')[0]
            if fileID not in label_dict:
                # print('key not exsist')
                continue
            # if fileID not in old_dict[cwe] or fileID not in new_dict[cwe]:  # 如果标签不成对则跳过
            #     continue
            # funcID = sentences[0].split(' @@ ')[2]
            # sliceID = ('_').join(sentences[0].split(' @@ ')[:3])  # 切片标记
            code_list = []
            code_label_list = []
            type_list=[]
            sentences = sentences[1:]
            flag = False
            graph_label=0

            for i in range(len(sentences)):
                sentence = sentences[i]
                # this_file = sentence.split(' file: ')[-1].strip()      # 获取当前行的文件名
                this_code = sentence.split(' location: ')[0].replace('\n', ' ').strip()   # 获取当前行的代码片段
                this_loc = sentence.split(' location: ')[-1].split(' file: ')[0].strip()  # 获取当前行的行号
                this_fileID = sentence.split(' file: ')[-1].split(' type: ')[0].strip().split('/')[-1][:-8]  # 获取当前行所属文件
                this_type=sentence.split(' type: ')[-1].split(' id: ')[0].strip() # 获取当前行类型
                code_list.append(this_code)
                if this_code=='':
                    # print(sentence)
                    empty_line=True
                if this_fileID in label_dict and  int (this_loc) in  label_dict[this_fileID]:
                    # flag = True
                    if type == 'old':
                        code_label_list.append(1)
                        graph_label=1
                    else:
                        code_label_list.append(2)
                else:
                    code_label_list.append(0)
                type_list.append(this_type)
            # if not flag:  # 没有漏洞的切片不要
            #     continue
            if empty_line:
                continue
            edges = edgelists[index].split('\n')
            if edges[0] == '\r' or edges[0] == '':
                del edges[0]
            if edges[-1] == '' or edges[-1] == '\r':
                del edges[-1]
            if len(edges)==1:
                continue

            code_label_edges.append((code_list, code_label_list, edges, graph_label,type_list,slicename,slice_file,cve))
            # if cwe+'/'+fileID not in filepath2sample:
            #     filepath2sample[cwe+'/'+fileID]=[]
            # filepath2sample[cwe+'/'+fileID].append((code_list, code_label_list, edges, type))

    return code_label_edges
    # return filepath2sample


def check_node_label(codes, edges):
    for edge in edges[1:]:
        a = int(edge.split(',')[0])
        b = int(edge.split(',')[1])
        if a<1 or b<1:
            return False
        if a > len(codes):
            return False
        if b > len(codes):
            return False
    return True
# def getSAGdata_batch(list_A,list_graph_indicator,list_graph_labels,list_node_labels,list_node_attributes_code,code_label_edges,type):
#     for tup in code_label_edges:
#         code_list,code_label_list,edges=tup
#         if check_node_label(code_list,edges)==False:
#             print(len(code_list),edges)
#             continue
#         for edge in edges[1:]:
#             a = int(edge.split(',')[0])
#             b = int(edge.split(',')[1])
#             new_a = a + len(list_node_attributes_code)
#             new_b = b + len(list_node_attributes_code)
#             list_A.append((new_a,new_b))
#         if type=='old':
#             list_graph_labels.append(1)
#         else:
#             list_graph_labels.append(0)

#         for code in code_list:
#             list_node_attributes_code.append(code)
#             list_graph_indicator.append(len(list_graph_labels))
#         list_node_labels+=code_label_list


# def getSAGdata_batch(list_A, list_graph_indicator, list_graph_labels, list_node_labels, list_node_attributes_code, code_label_edges, graph_num):
#     for tup in code_label_edges:
#         code_list, code_label_list, edges, type = tup
#         if check_node_label(code_list, edges) == False:
#             print(len(code_list), edges)
#             continue
#         for edge in edges[1:]:
#             a = int(edge.split(',')[0])
#             b = int(edge.split(',')[1])
#             new_a = a + len(list_node_attributes_code)
#             new_b = b + len(list_node_attributes_code)
#             list_A.append((new_a, new_b))
#         if type == 'old':
#             list_graph_labels.append(1)
#             graph_num[1] += 1
#         else:
#             list_graph_labels.append(0)
#             graph_num[0] += 1

#         for code in code_list:
#             list_node_attributes_code.append(code)
#             list_graph_indicator.append(len(list_graph_labels))
#         list_node_labels += code_label_list


def getSAGdata_batch(data_type, cle_tup_list_type):
    list_A = []
    list_graph_indicator = []
    list_graph_labels = []
    list_node_labels = []
    list_node_attributes_code = []
    SAGPool_Data_path = '/home/wanghu/SAGPool/data/preprocess/'+data_type+'/raw'
    graph_num = [0, 0]
    cle_tup_list = []

    # for batch in cle_tup_list_type:
    #     cle_tup_list += batch
    # random.shuffle(cle_tup_list)
    cle_tup_list=cle_tup_list_type
    print('* '+data_type)
    print('graph num:', len(cle_tup_list))
    for tup in cle_tup_list:
        code_list, code_label_list, edges, type = tup
        ret=check_node_label(code_list, edges) 
        if not ret:
            print('* wrong',len(code_list), edges)
            continue
        for edge in edges[1:]:
            a = int(edge.split(',')[0])
            b = int(edge.split(',')[1])
            
            new_a = a + len(list_node_attributes_code)
            new_b = b + len(list_node_attributes_code)
           
            list_A.append((new_a, new_b))
        if type == 1:
            list_graph_labels.append(1)
            graph_num[1] += 1
        else:
            list_graph_labels.append(0)
            graph_num[0] += 1

        for code in code_list:
            list_node_attributes_code.append(code)
            list_graph_indicator.append(len(list_graph_labels))
        list_node_labels += code_label_list

    print(graph_num)

    if not os.path.exists(SAGPool_Data_path):
        os.makedirs(SAGPool_Data_path)

    store_filepath = os.path.join(SAGPool_Data_path, f"{data_type}_A.txt")
    f = open(store_filepath, 'w+')
    for edge in list_A:
        f.write(str(edge[0]) + "," + str(edge[1]) + '\n')
    f.close()

    store_filepath = os.path.join(SAGPool_Data_path, f"{data_type}_graph_indicator.txt")
    f = open(store_filepath, 'w+')
    for dicator in list_graph_indicator:
        f.write(str(dicator) + '\n')
    f.close()

    store_filepath = os.path.join(SAGPool_Data_path, f"{data_type}_graph_labels.txt")
    f = open(store_filepath, 'w+')
    for label in list_graph_labels:
        f.write(str(label) + '\n')
    f.close()

    store_filepath = os.path.join(SAGPool_Data_path, f"{data_type}_attributes_code.txt")
    f = open(store_filepath, 'w+')
    for code in list_node_attributes_code:
        f.write(code + '\n')
    f.close()

    store_filepath = os.path.join(SAGPool_Data_path, f"{data_type}_focus_labels.txt")
    f = open(store_filepath, 'w+')
    for label in list_node_labels:
        f.write(str(label) + '\n')
    f.close()

def del_dup_slice(code_label_edges1,code_label_edges2):
    hash2tup1={}
    hash2tup2={}
    # hashset=set()

        
    # md5 = hashlib.md5()
    # md5.update(.encode('utf-8'))


    del_num=[0,0]

    for tup in code_label_edges1:
        code_list, code_label_list, edges, graph_label,type_list,slicename,slice_file,cve = tup
        code_content=''
        for code in code_list:
            code_content+=code
        for edge in edges[1:]:
            code_content+=edge
        md5 = hashlib.md5()
        md5.update(code_content.encode('utf-8'))
        code_hash=md5.hexdigest()
        if code_hash in hash2tup1:
            # print('dup')
            del_num[0]+=1
            # hash2tup[code_hash]=None
        # else:
        hash2tup1[code_hash]=tup#对于重复切片，用最新的替代
    
    for tup in code_label_edges2:
        code_list, code_label_list, edges, graph_label,type_list,slicename,slice_file,cve= tup
        # code_hash=hash(str(code_list))
        code_content=''
        for code in code_list:
            code_content+=code
        for edge in edges[1:]:
            code_content+=edge
        # code_hash=hash(code_content)
        md5 = hashlib.md5()
        md5.update(code_content.encode('utf-8'))
        code_hash=md5.hexdigest()
        if code_hash in hash2tup2:
            # print('dup')
            del_num[1]+=1
     
        hash2tup2[code_hash]=tup

    
    ret_list=[]
    del_num=[0,0]
    for hash_vale in hash2tup1:
        if  hash_vale not in hash2tup2:
            ret_list.append(hash2tup1[hash_vale])
        else:
            del_num[0]+=1

    for hash_vale in hash2tup2:
        if  hash_vale not in hash2tup1:
            ret_list.append(hash2tup2[hash_vale])
        else:
            del_num[1]+=1
    # print('remian_num',len(ret_list))
    # if del_num!=[0,0]:
    # print('oldnew_dup',del_num)
    return ret_list

def del_dup_all(cle_list):
    hash2tup={}
    del_num=0
    i=0
    for tup in cle_list:
        code_list, code_label_list, edges, graph_label,type_list,slicename,slice_file,cve = tup
        code_content=''
        for code in code_list:
            code_content+=code
        for edge in edges:
            code_content+=(str(edge[0])+','+str(edge[1]))
        md5 = hashlib.md5()
        md5.update(code_content.encode('utf-8'))
        code_hash=md5.hexdigest()
        if code_hash in hash2tup:
            # print('dup')
            del_num+=1
            if hash2tup[code_hash][3]==0:
                hash2tup[code_hash]=tup
            if graph_label!=hash2tup[code_hash][3]:
                i+=1
            #     # print('slice error')
            #     tup=
            # hash2tup[code_hash]=None
        # else:
        else:
            hash2tup[code_hash]=tup#对于重复切片，用最新的替代
    print('delnum',del_num)
    print('dup but label different',i)
    new_list=[]
    for codehash in hash2tup:
        new_list.append(hash2tup[codehash])
    return new_list

def choose_cle(cle_list):
    old_tle_dict={}
    new_tle_dict={}
    cuplist=[]
    newlist=[]
    ret_list=[]
    ret_cup_len=0
    
    for code_list, code_label_list, edges, graph_label,slicename,slicefile in cle_list:
        if graph_label==1:
            if slicename not in old_tle_dict:
                old_tle_dict[slicename]=[]
            old_tle_dict[slicename].append((code_list, code_label_list, edges,graph_label,slicename))
        else:
            if slicename not in new_tle_dict:
                # print(f'new {slicename} exists')
                new_tle_dict[slicename]=[]
            new_tle_dict[slicename].append((code_list, code_label_list, edges,graph_label,slicename))

    print('len(old_tle_dict)',len(old_tle_dict))
    print('len(new_tle_dict)',len(new_tle_dict))
    for slicename in old_tle_dict:
        for tup in old_tle_dict[slicename]:
            cuplist.append(tup)
        # if slicename in new_tle_dict:
        #     cuplist.append(new_tle_dict[slicename])
    print('len(cuplist)',len(cuplist))
    ret_cup_len=len(cuplist)
    new_len=0
    for slicename in new_tle_dict:
        if slicename not in old_tle_dict:
            for tup in new_tle_dict[slicename]:
                newlist.append(tup)
        else:
            for tup in new_tle_dict[slicename]:
                cuplist.append(tup)
                new_len+=1

    print('len(cuplist)',len(cuplist))
    print('len(newlist)',len(newlist))

    random.shuffle(newlist)
    ret_list=cuplist+newlist[:ret_cup_len-new_len]
    random.shuffle(ret_list)
    return ret_list


def source2process(param):
    index,sentences=param
    # sentence_word_count=[]

    for sentence in sentences:
        sentence = sentence.strip()
        list_tokens = create_tokens(sentence)
        slice_corpus.append(list_tokens)

    # print(slice_corpus)
    sentence_len = []
    for i in slice_corpus:
        sentence_len.append(len(i))

    slice_corpus, slice_func = mapping(slice_corpus)

    return index,slice_corpus,sentence_len
    
def multi_process(ret_list):
    paramlist=[]
    slice_copus=[]
    line_word_cnt=[]
    for i,tup in enumerate(ret_list):
        code_list, code_label_list, edges,graph_label=tup
        paramlist.append([i+1,code_list])
    with multiprocessing.Pool(16)as p:
        
        multi_ret = p.imap_unordered(source2process, paramlist)
        for ret in tqdm(multi_ret):
            i,sample_corpus,sentence_word_count=ret
            slice_corpus.append(sample_corpus)
            line_word_cnt[i]=sentence_word_count

    # with open ("./corpus/DATA_process_file.pkl", "wb")as f:
    #     pickle.dump([slice_corpus, line_word_cnt], f,protocol=pickle.HIGHEST_PROTOCOL)
    return slice_corpus, line_word_cnt


def trainw2vmodel(slice_corpus,w2v_model_path):
    # w2v_model_path = "./w2v_model/word2vec_model_funded"
    if not os.path.exists('./w2v_model'):
        os.mkdir('./w2v_model')
    print("training...")
    model = Word2Vec(sentences= slice_corpus, vector_size=40, alpha=0.01, window=15, min_count=0, max_vocab_size=None, sample=0.001, seed=1, workers=1, min_alpha=0.0001, sg=1, hs=1, negative=5, epochs=5)
    model.save(w2v_model_path)

def evaluate_w2vModel(w2vModelPath):

    print("\nevaluating...")
    model = Word2Vec.load(w2vModelPath)
    print("vocabulary number",len(model.wv.index_to_key)) 
    # for voc in model.wv.index2word:
    #     print(voc)
      
    for sign in ['(', '+', '-', '*', 'func_1','variable_1']:
        print(sign, ":")
        print(model.wv.most_similar_cosmul(positive=[sign], topn=10))

def generate_vector(w2vModelPath, samples):
    model = Word2Vec.load(w2vModelPath)
    print("begin generate input...")
    # dl_corpus = [[model.wv[word] for word in sample] for sample in samples]
    dl_corpus =[]
    for sample in tqdm(samples):
        sample_copus=[]
        for word in sample:
            sample_copus.append(model.wv[word])
        dl_corpus.append(sample_copus)
    print("generate input success...")
    return dl_corpus

def del_far_nodes(code_label_list,edges,distance):
    edge_list=[]
    for edge in edges[1:]:
        edge_list.append((int(edge.split(',')[0]),int(edge.split(',')[1])))
    
    g=ig.Graph(edges=edge_list)
    # ig.summary(g)
    source_nodes=[]
    for i,label in enumerate(code_label_list):
        if label:
            source_nodes.append(i+1)
    
    distance_adj_in=g.distances(source=source_nodes,mode='in')
    node_remain_label=[0]*(len(code_label_list)+1)
    for l in distance_adj_in:
        # print(l)
        for i,dist in enumerate(l):
            if dist ==inf:
                continue
            elif dist<=distance:
                node_remain_label[i]=1
    distance_adj_out=g.distances(source=source_nodes,mode='out')
    # node_remain_label=[0]*(len(code_label_list)+1)
    for l in distance_adj_out:
        # print(l)
        for i,dist in enumerate(l):
            if dist ==inf:
                continue
            elif dist<=distance:
                node_remain_label[i]=1
    del_node_set=set()
    for i,label in enumerate(node_remain_label):
        if label==0:
            del_node_set.add(i)
    print('len_del:',len(del_node_set))
        
    id2index={}
    index=0
    new_node_list=[]
    for i in range(1,len(code_label_list)+1):
        if i in del_node_set:
            continue
        else:
            index+=1
            id2index[i]=index
            new_node_list.append(i-1)
    new_edge_list=[]
    for i,edge in enumerate (edge_list):
        if edge[0] in del_node_set or edge[1] in del_node_set:
            continue
        else:
            new_edge_list.append((id2index[edge[0]],id2index[edge[1]]))
            # new_edge_list.append(i+1)
    print('del_edge_num:',len(edge_list)-len(new_edge_list))

    return new_node_list,new_edge_list,distance_adj_in,distance_adj_out


if __name__ == '__main__':

    # cwe_list=['CWE-119','CWE-20','CWE-189','CWE-200','CWE-264','CWE-362','CWE-399','CWE-416','CWE-476']
    # cwe_list=['CWE-119','CWE-119_*']
    cwe_list=['CWE-119']
    cle_tup_list = []
    cve_list=[]
    for cwe in cwe_list:
        # if cwe not in ['CWE-119','CWE-20','CWE-189','CWE-200','CWE-264']:
        # if cwe not in ['CWE-20']:
        #     continue

        print('*',cwe)
        root_dir = os.path.join('/home/wanghu/SAGPool/data2slice/slice_all/NVD/',cwe)


        f = open('/home/wanghu/SAGPool/data2slice/code/pkl/'+cwe+'_linenum_dict.pkl', 'rb')
        linenum_dict = pickle.load(f)
        f.close()
        # f = open('/home/wanghu/SAGPool/data2slice/code/pkl/'+cwe+'_new.pkl', 'rb')
        # new_dict = pickle.load(f)
        # f.close()
        new_dict=linenum_dict['new']
        old_dict=linenum_dict['old']


        i=0
        for batch in os.listdir(root_dir):

            for cve in os.listdir(os.path.join(root_dir, batch)):

                if not os.path.exists(os.path.join(root_dir, batch, cve, 'old','logs', 'output.txt')):

                    code_label_edges1 = get_codes_labels_and_edges(os.path.join(root_dir,batch, cve,'old'), old_dict, new_dict, 'old')
                
                if not os.path.exists(os.path.join(root_dir, batch, cve,'new', 'logs', 'output.txt')):

                    code_label_edges2 = get_codes_labels_and_edges(os.path.join(root_dir, batch, cve,'new'), old_dict, new_dict, 'new')
                
                batch_tup=del_dup_slice(code_label_edges1,code_label_edges2)
                cle_tup_list+=batch_tup
                # cle_tup_list+=code_label_edges1

    # new_edge=[]
    # new_cle_list=[]
    # for i,tup in enumerate (cle_tup_list):
    #     code_list, code_label_list, edges, graph_label,type_list,slicename,slice_file,cve = tup
    #     # new_node_list,new_edge_list,distance_adj_in,distance_adj_out=del_far_nodes(code_label_list,edges,3)
    #     new_code=[]
    #     new_label=[]
    #     for index in new_node_list:
    #         new_code.append(code_list[index])
    #         new_label.append(code_label_list[index])
    #     # cle_tup_list[i]=(new_code,new_label,new_edge_list,graph_label,type_list,slicename,slice_file,cve)
    #     if len(new_code)>100:
    #         continue
    #     else:
    #         new_cle_list.append((new_code,new_label,new_edge_list,graph_label,type_list,slicename,slice_file,cve))


    cle_tup_list=del_dup_all(cle_tup_list)
    random.shuffle(cle_tup_list)
    vul=0
    nonvul=0
    for tup in cle_tup_list:
        code_list, code_label_list, edges, graph_label,type_list,slicename,slice_file,cve = tup
        if graph_label:
            vul+=1
        else:
            nonvul+=1
    print('vul:',vul,'nonvul:',nonvul)
    print('sumlen:',len(cle_tup_list))

    with open('/home/wanghu/SAGPool/data_preprocess/cle_tup_list_cwe119_all.pkl','wb')as f:
        pickle.dump(cle_tup_list,f,protocol=2)

        
        # getSAGdata_batch('realdata', cle_tup_list,cwe,cve_list)
        # print(slice_all_len)


    