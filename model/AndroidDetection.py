from libraries.AgvSim import AvgSim
from libraries.libraries import create_vector_with_label, get_apis, load_pkl, create_app_api_matrix
import numpy as np
import shutil


class AndroidDetection:
    def __init__(self):
        self.__api_dataset = load_pkl('./data_12000_app/api_dataset.pkl')
        self.__app_api = load_pkl('./data_12000_app/app_api.pkl')
        self.__invoke = load_pkl('./data_12000_app/invoke.pkl')
        self.__package = load_pkl('./data_12000_app/package.pkl')
        self.__method = load_pkl('./data_12000_app/method.pkl')
        self.__feature_vector = load_pkl('./data_12000_app/feature_vector_v32.pkl')
        self.__label = load_pkl('./data_12000_app/label.pkl')
        # self.__benign = self.__label.size - self.__label.sum()
        self.__benign = self.__label.sum()

    def create_app_vector(self, path):
        data = get_apis(path=path, api_dataset=self.__api_dataset)
        self.__app_api = np.vstack([self.__app_api, create_app_api_matrix(data)])
        avg_sim = AvgSim(self.__app_api, self.__invoke, self.__package, self.__method)
        feature_vector = create_vector_with_label(avg_sim, self.__benign)
        test_feature_vector = [feature_vector[len(feature_vector) - 1]]
        shutil.rmtree(path=path)
        return test_feature_vector
