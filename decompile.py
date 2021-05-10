from libraries.libraries import decompile_apk
from os import listdir
from os.path import isfile, join

MALWARE_PATH = '/Volumes/KhanhKD/KHANH/apk/test2000_1000/malware'
BENIGN_PATH = '/Volumes/KhanhKD/KHANH/apk/test2000_1000/benign'

if __name__ == '__main__':
    malware_files = [f for f in listdir(MALWARE_PATH) if isfile(join(MALWARE_PATH, f)) and not f.startswith('.')]
    benign_files = [f for f in listdir(BENIGN_PATH) if isfile(join(BENIGN_PATH, f))]

    print(f'Số lượng app malware: {len(set(malware_files))}')
    print(f'Số lượng app benign: {len(benign_files)}')

    matrix_test_apps = []

    for i, malware_file in enumerate(malware_files):
        print(f'##### MALWARE {i}: {malware_file}')
        print(decompile_apk(path=MALWARE_PATH, apk_file=malware_file, decompile_folder='/Volumes/KhanhKD/KHANH/apk'
                                                                                       '/test2000_1000/decompile_folder'
                                                                                       '/malware'))

    for i, benign_file in enumerate(benign_files):
        print(f'##### BENIGN {i}: {benign_file}')
        print(decompile_apk(path=BENIGN_PATH, apk_file=benign_file, decompile_folder='/Volumes/KhanhKD/KHANH/apk'
                                                                                     '/test2000_1000/decompile_folder'
                                                                                     '/benign'))
