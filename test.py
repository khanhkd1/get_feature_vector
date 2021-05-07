from model.AndroidDetection import AndroidDetection
from libraries.libraries import decompile_apk, save_pkl
from os import listdir
from os.path import isfile, join
import numpy as np

MALWARE_PATH = '/Users/xxxibkhnhkd/Downloads/bộ_test_apk_2000malware_1000benign/malware'
BENIGN_PATH = '/Users/xxxibkhnhkd/Downloads/bộ_test_apk_2000malware_1000benign/benign'


if __name__ == '__main__':
    model = AndroidDetection()
    malware_files = [f for f in listdir(MALWARE_PATH) if isfile(join(MALWARE_PATH, f))]
    benign_files = [f for f in listdir(BENIGN_PATH) if isfile(join(BENIGN_PATH, f))]

    matrix_test_apps = []

    for i, malware_file in enumerate(malware_files):
        print(f'##### STT {i}: {malware_file}')
        vector = model.create_app_vector(decompile_apk(path=MALWARE_PATH, apk_file=malware_file))[0].tolist() + [1]
        print(vector)
        matrix_test_apps.append(vector)

    for i, benign_file in enumerate(benign_files):
        print(f'##### STT {i}: {benign_file}')
        vector = model.create_app_vector(decompile_apk(path=BENIGN_PATH, apk_file=benign_file))[0].tolist() + [0]
        print(vector)
        matrix_test_apps.append(vector)

    save_pkl('./data_12000_app/matrix_test_apps.pkl', np.array(matrix_test_apps))
