import os
import numpy as np
import re
import pickle
from collections import defaultdict


def decompile_apk(path, apk_file, decompile_folder='./decompile_folder'):
    if not os.path.exists(decompile_folder):
        os.makedirs(decompile_folder)
    apk_file_name = apk_file.replace('.apk', '')
    os.system(f"apktool d {path}/{apk_file} -o {decompile_folder}/{apk_file_name} -f")
    return f"{decompile_folder}/{apk_file_name}"


"""--------------------------------------------------------"""


def save_pkl(path, obj):
    with open(path, 'wb') as f:
        pickle.dump(obj, f)


def load_pkl(path):
    with open(path, 'rb') as f:
        obj = pickle.load(f)
    return obj


"""--------------------------------------------------------"""


def create_vector_with_label(avg_sim, benign):
    result = np.full((1, 32), 0.0, dtype=float)
    buffer = avg_sim.meta_path_1().tolist()
    result[0][0] = np.sum(buffer[0][:benign])
    result[0][1] = np.sum(buffer[0][benign:])
    print('done 1')
    buffer = avg_sim.meta_path_2().tolist()
    result[0][2] = np.sum(buffer[0][:benign])
    result[0][3] = np.sum(buffer[0][benign:])
    print('done 2')
    buffer = avg_sim.meta_path_3().tolist()
    result[0][4] = np.sum(buffer[0][:benign])
    result[0][5] = np.sum(buffer[0][benign:])
    print('done 3')
    buffer = avg_sim.meta_path_4().tolist()
    result[0][6] = np.sum(buffer[0][:benign])
    result[0][7] = np.sum(buffer[0][benign:])
    print('done 4')
    buffer = avg_sim.meta_path_5().tolist()
    result[0][8] = np.sum(buffer[0][:benign])
    result[0][9] = np.sum(buffer[0][benign:])
    print('done 5')
    buffer = avg_sim.meta_path_6().tolist()
    result[0][10] = np.sum(buffer[0][:benign])
    result[0][11] = np.sum(buffer[0][benign:])
    print('done 6')
    buffer = avg_sim.meta_path_7().tolist()
    result[0][12] = np.sum(buffer[0][:benign])
    result[0][13] = np.sum(buffer[0][benign:])
    print('done 7')
    buffer = avg_sim.meta_path_8().tolist()
    result[0][14] = np.sum(buffer[0][:benign])
    result[0][15] = np.sum(buffer[0][benign:])
    print('done 8')
    buffer = avg_sim.meta_path_9().tolist()
    result[0][16] = np.sum(buffer[0][:benign])
    result[0][17] = np.sum(buffer[0][benign:])
    print('done 9')
    buffer = avg_sim.meta_path_10().tolist()
    result[0][18] = np.sum(buffer[0][:benign])
    result[0][19] = np.sum(buffer[0][benign:])
    print('done 10')
    buffer = avg_sim.meta_path_11().tolist()
    result[0][20] = np.sum(buffer[0][:benign])
    result[0][21] = np.sum(buffer[0][benign:])
    print('done 11')
    buffer = avg_sim.meta_path_12().tolist()
    result[0][22] = np.sum(buffer[0][:benign])
    result[0][23] = np.sum(buffer[0][benign:])
    print('done 12')
    buffer = avg_sim.meta_path_13().tolist()
    result[0][24] = np.sum(buffer[0][:benign])
    result[0][25] = np.sum(buffer[0][benign:])
    print('done 13')
    buffer = avg_sim.meta_path_14().tolist()
    result[0][26] = np.sum(buffer[0][:benign])
    result[0][27] = np.sum(buffer[0][benign:])
    print('done 14')
    buffer = avg_sim.meta_path_15().tolist()
    result[0][28] = np.sum(buffer[0][:benign])
    result[0][29] = np.sum(buffer[0][benign:])
    print('done 15')
    buffer = avg_sim.meta_path_16().tolist()
    result[0][30] = np.sum(buffer[0][:benign])
    result[0][31] = np.sum(buffer[0][benign:])
    print('done 16')
    return result


"""--------------------------------------------------------"""


def list_smali_file(path):
    list_smali = []
    for root, _, filenames in os.walk(path):
        for filename in filenames:
            if filename.endswith('.smali'):
                list_smali.append(os.path.join(root, filename))
    return list_smali


def cut_to_special_element_of_api(a):
    try:
        invoke = a[:a.find(' ')]
        api = a[a.index('}, ') + 3:a.index('->') + 2]
        for i in range(a.index(';->') + 3, len(a)):
            if not (a[i].isalpha() or a[i] == '<' or a[i] == '>'):
                break
            api = api + a[i]
        return [api, invoke, api[:api.find('->')]]
    except ValueError:
        return ['']


def extract_api(api_dataset, path):
    data = defaultdict(lambda: [])
    for a in api_dataset:
        data[a] = [[], [], '']
    for smaliFile in list_smali_file(path):
        try:
            file_content = open(smaliFile, "r").readlines()
            pass
        except IOError:
            pass
        else:
            i = 0
            while i < len(file_content):
                if re.search(r'^.method', file_content[i]):
                    method_name = file_content[i][:file_content[i].find('(')]
                    while i < len(file_content) and not re.search(r'^.end method', file_content[i]):
                        file_content[i] = file_content[i].strip()
                        if re.search(r'^invoke', file_content[i]):
                            a = cut_to_special_element_of_api(file_content[i])
                            if a[0] in api_dataset:
                                if a[1] not in data[a[0]][0]:
                                    data[a[0]][0].append(a[1])
                                if a[2] not in data[a[0]][1]:
                                    data[a[0]][1].append(method_name)
                                data[a[0]][2] = a[2]
                        i = i + 1
                i = i + 1
    data['label'] = 0
    return dict(data)


def get_apis(path, api_dataset):
    return extract_api(api_dataset=api_dataset, path=path)


"""--------------------------------------------------------"""


def create_app_api_matrix(extract_data):
    api_dataset = list(extract_data.keys())[:-1]
    # row = [1 if extract_data[api][0] else 0 for api in api_dataset]
    row = []
    for api in api_dataset:
        row.append(1 if extract_data[api][0] else 0)
    return np.array([row])
