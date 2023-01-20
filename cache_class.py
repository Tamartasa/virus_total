import os
import pickle


class Cache:
    def __init__(self, base_prefix, file_path):
        self.path = os.path.join(base_prefix, file_path)

        if not os.path.exists(self.path):
            self.data = {}
        else:
            with open(self.path, 'rb') as handle:
                print('loading info from cache')
                self.data = pickle.load(handle)

    def get_entry(self, url):
        return self.data.get(url, None)

    def add_entry(self, url, data):
        self.data[url] = data

    def remove_entry(self, url):
        del self.data[url]

    def save(self):
        with open(self.path, 'wb') as handle:
            pickle.dump(self.data, handle, protocol=pickle.HIGHEST_PROTOCOL)