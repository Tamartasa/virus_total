import os
import pickle
from threading import Lock


class Cache:
    def __init__(self, base_prefix, file_path):
        self.path = os.path.join(base_prefix, file_path)
        self.lock = Lock()

        if not os.path.exists(self.path):
            self.data = {}
        else:
            with open(self.path, 'rb') as handle:
                print('loading info from cache')
                self.lock.acquire()
                self.data = pickle.load(handle)
                self.lock.release()

        # copy for original_data
        if not self.data:
            self.original_data = {}
        else:
            with open(self.path, 'rb') as handle:
                print('loading info from cache for original_data copy')
                self.lock.acquire()
                self.original_data = pickle.load(handle)
                self.lock.release()

    def get_entry(self, url):
        # lock?
        return self.data.get(url, None)

    def add_entry(self, url, data):
        self.lock.acquire()
        self.data[url] = data
        self.lock.release()

    def remove_entry(self, url):
        self.lock.acquire()
        del self.data[url]
        self.lock.release()

    def save(self):
        try:
            with open(self.path, 'wb') as handle:
                self.lock.acquire()
                pickle.dump(self.data, handle, protocol=pickle.HIGHEST_PROTOCOL)
                self.lock.release()
        except:
            Exception("Saved failed")

