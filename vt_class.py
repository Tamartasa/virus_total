import base64
import datetime

import requests

from cache_class import Cache


class VtManager:
    def __init__(self, urls, is_force_scan, api_key):
        self.cache = Cache('C:\\Users\\tamar\Desktop\\full_stack_course\\virus_total', 'cache.pickle')
        self.original_data = self.cache.data

        self.is_force_scan = is_force_scan
        self.api_key = api_key
        self.urls = urls
        self.vt_url = "https://www.virustotal.com/api/v3/urls"
        self.days = 180

    def execute_all(self):
        s = ''

        for url in self.urls:
            data = self.execute_url(url)  # not cpu
            s += str(data) + '\n'  # cpu

        return s[:-1]

    def execute_url(self, url):
        # check if url exists
        if not self.is_valid_url(url):
            raise Exception(f'the url does not exist, {url}')

        # check if already in cache (only works if force scan is False)
        if not self.is_force_scan:
            if url in self.cache.data:
                data = self.cache.data[url]

                # if the date is not valid, remove from cache and carry on to get from virustotal
                if self.is_valid_date(data['last_analysis_date']):
                    return data
                else:
                    self.cache.remove_entry(url)

        # if not, get from virustotal (only works if force scan is False)
        if not self.is_force_scan:
            data = self.get_url_data_virustotal(url)

            # if the date is not valid, carry on to scan
            # if it is, add to cache and return
            if data is not None and self.is_valid_date(data['last_analysis_date']):
                self.cache.add_entry(url, data)
                return data

        # if does not exist in virustotal or date invalid, scan it, and get again
        self.scan_url(url)
        data = self.get_url_data_virustotal(url)

        if data is not None:
            self.cache.add_entry(url, data)
            return data

    @staticmethod
    def is_valid_date(date):
        # check if pass 6 months or more from the last analysis date
        today = datetime.datetime.now()
        analysis_date = datetime.datetime.fromtimestamp(date)
        delta = (today - analysis_date).days
        if delta >= 180:
            return False
        else:
            return True

    @staticmethod
    def is_valid_url(url):
        response = requests.get(url, headers={'User-Agent': 'Mozilla 5.0'})
        return response.status_code == 200

    def get_url_data_virustotal(self, url):
        # sending GET request to virustotal with the url
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        url_vt = "https://www.virustotal.com/api/v3/urls/"
        new_url = url_vt + url_id
        headers = {
            "accept": "application/json",
            "x-apikey": self.api_key
        }
        response = requests.get(new_url, headers=headers)

        if response.status_code != 200 or response.text is None:
            return None

        data = response.json()
        data_url = {'url': url,
                    'reputation': data["data"]["attributes"]["reputation"],
                    'last_analysis_date': data["data"]["attributes"]["last_analysis_date"]}
        return data_url

    def scan_url(self, url):
        # sending POST request to virustotal with the url
        form_data = "url=" + url

        headers = {
            "accept": "application/json",
            "content-type": "application/x-www-form-urlencoded",
            "x-apikey": self.api_key
        }

        response = requests.post(self.vt_url, data=form_data, headers=headers)

        if response.status_code != 200:
            raise Exception(f"scan failed. {url} go error response: {response.status_code}")

        data_scan = response.json()

    def update_cache(self):
        if self.original_data != self.cache.data:
            print("saving to cache")
            self.cache.save()