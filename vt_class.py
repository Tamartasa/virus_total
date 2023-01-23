import base64
import concurrent
import datetime
from concurrent.futures import ThreadPoolExecutor

import requests

from cache_class import Cache


class VtManager:
    def __init__(self, urls, is_force_scan, api_key, max_days):
        self._cache = Cache('C:\\Users\\tamar\Desktop\\full_stack_course\\virus_total', 'cache.pickle')
        self._original_data = self._cache.original_data

        self._is_force_scan = is_force_scan
        self._api_key = api_key
        self._headers = {
            "accept": "application/json",
            "content-type": "application/x-www-form-urlencoded",
            "x-apikey": self._api_key
        }
        self.urls = urls
        self.vt_url = "https://www.virustotal.com/api/v3/urls"
        self.max_days = max_days

    def _execute_all(self):
        futures = []
        with ThreadPoolExecutor(max_workers=4) as executor:
            for url in self.urls:
                futures.append(executor.submit(self._execute_url, url))
            for f in concurrent.futures.as_completed(futures):
                print(f.result())
        # s = ''
        #
        # for url in self.urls:
        #     data = self.execute_url(url)  # not cpu
        #     s += str(data) + '\n'  # cpu
        #
        # return s[:-1]

    def _execute_url(self, url):
        # check if url exists
        if not self._is_valid_url(url):
            raise Exception(f'the url does not exist, {url}')

        # check if already in cache (only works if force scan is False)
        if not self._is_force_scan:
            if url in self._cache.data:
                data = self._cache.data[url]

                # if the date is not valid, remove from cache and carry on to get from virustotal
                if self._is_valid_date(data['last_analysis_date']):
                    return data
                else:
                    self._cache.remove_entry(url)

        # if not, get from virustotal (only works if force scan is False)
        if not self._is_force_scan:
            data = self._get_url_data_virustotal(url)

            # if the date is not valid, carry on to scan
            # if it is, add to cache and return
            if data is not None and self._is_valid_date(data['last_analysis_date']):
                self._cache.add_entry(url, data)
                return data

        # if does not exist in virustotal or date invalid, scan it, and get again
        self._scan_url(url)
        data = self._get_url_data_virustotal(url)

        if data is not None:
            self._cache.add_entry(url, data)
            return data


    def _is_valid_date(self, date):
        # check if pass 6 months or more from the last analysis date
        today = datetime.datetime.now()
        analysis_date = datetime.datetime.fromtimestamp(date)
        delta = (today - analysis_date).days
        if delta >= self.max_days:
            return False
        else:
            return True

    @staticmethod
    def _is_valid_url(url):
        try:
            response = requests.get(url, headers={'User-Agent': 'Mozilla 5.0'})
            return response.status_code == 200
        except:
            Exception("RESPONSE ERROR")

    def _get_url_data_virustotal(self, url):
        # sending GET request to virustotal with the url
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        url_vt = "https://www.virustotal.com/api/v3/urls/"
        new_url = url_vt + url_id
        headers = self._headers
        response = requests.get(new_url, headers=headers)

        if response.status_code != 200 or response.text is None:
            return None

        data = response.json()
        data_url = {'url': url,
                    'reputation': data["data"]["attributes"]["reputation"],
                    'last_analysis_date': data["data"]["attributes"]["last_analysis_date"]}
        return data_url

    def _scan_url(self, url):
        # sending POST request to virustotal with the url
        form_data = "url=" + url

        headers = self._headers

        response = requests.post(self.vt_url, data=form_data, headers=headers)

        if response.status_code != 200:
            raise Exception(f"scan failed. {url} go error response: {response.status_code}")

        data_scan = response.json()
        # now the url details scan in virus total - and we can GET them

    def update_cache(self):
        if self._original_data != self._cache.data:
            print("saving to cache")
            self._cache.save()