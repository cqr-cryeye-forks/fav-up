#!/usr/bin/env python3

import argparse
import base64
import json
import os
import time
from typing import Optional, List

import mmh3
import requests
from bs4 import BeautifulSoup
from fake_useragent import UserAgent
from fake_useragent.errors import FakeUserAgentError
from ipwhois import IPWhois
from shodan import Shodan
from shodan.cli.helpers import get_api_key
from tqdm import tqdm


class FavUp:
    FALLBACK_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"

    def __init__(self, show: Optional[bool] = None):
        self.show = show
        self.shodan: Optional[Shodan] = None
        self.api_key: Optional[str] = None
        self.key_file: Optional[str] = None
        self.use_shodan_cli: Optional[bool] = None
        self.favicon_files: List[str] = []
        self.favicon_urls: List[str] = []
        self.websites: List[str] = []
        self.favicon_hashes: List[str] = []
        self.file_list: List[str] = []
        self.url_list: List[str] = []
        self.web_list: List[str] = []
        self.favicons_list: List[dict] = []
        self.current_work_dir = os.getcwd()
        self.ua = UserAgent(fallback=self.FALLBACK_UA)
        self.output: Optional[str] = None
        self.output_file: Optional[dict] = None
        self.iterator: Optional[tqdm] = None

        if self.show:
            self.setup_argparse()

    def setup_argparse(self):
        parser = argparse.ArgumentParser(prog="favup", usage="python3 %(prog)s [options]")
        parser.add_argument('-kf', '--key-file', help="Specify the file which contains the API key.")
        parser.add_argument('-k', '--key', help="Specify the API key.")
        parser.add_argument('-sc', '--shodan-cli', help="Load the API key from Shodan CLI.", action="store_true")
        parser.add_argument('-ff', '--favicon-file', help="Load the favicon icon from a local file.")
        parser.add_argument('-fu', '--favicon-url', help="Load the favicon icon from an URL.")
        parser.add_argument('-w', '--web', help="Extracts the favicon location from the page.")
        parser.add_argument('-fh', '--favicon-hash', help='Running from direct favicon hash number')
        parser.add_argument('-fl', '--favicon-list', help="Iterate over a file with the paths of icons to lookup.")
        parser.add_argument('-ul', '--url-list', help="Iterate over a file with URLs of icons to lookup.")
        parser.add_argument('-wl', '--web-list', help="Iterate over a file with domains to lookup.")
        parser.add_argument('-o', '--output', help="Specify output file, currently supported formats are CSV and JSON.")

        args = parser.parse_args()
        self.check_args(args)
        self.run()

    def check_args(self, args: argparse.Namespace):
        if not (args.key_file or args.key or args.shodan_cli):
            print('[x] Please specify the key with --key, --key-file or --shodan-cli.')
            exit(1)

        if not (args.favicon_file or args.favicon_url or args.web or args.favicon_list or args.url_list or args.web_list or args.favicon_hash):
            print('[x] Please specify the source of the favicon with --favicon-file, --favicon-url, --favicon-hash, --web, --favicon-list, --url-list or --web-list.')
            exit(1)

        self.api_key = args.key
        self.key_file = args.key_file
        self.use_shodan_cli = args.shodan_cli
        if args.favicon_file:
            self.favicon_files.append(args.favicon_file)
        if args.favicon_url:
            self.favicon_urls.append(args.favicon_url)
        if args.favicon_hash:
            self.favicon_hashes.append(args.favicon_hash)
        if args.web:
            self.websites.append(args.web)
        if args.favicon_list:
            self.file_list.extend(self.serialize_list_file(args.favicon_list))
        if args.url_list:
            self.url_list.extend(self.serialize_list_file(args.url_list))
        if args.web_list:
            self.web_list.extend(self.serialize_list_file(args.web_list))
        self.output = args.output

        self.iterator = tqdm(total=len(self.file_list) + len(self.url_list) + len(self.web_list))

        if self.output:
            self.output_file = {
                'type': self.output.split('.')[1],
                'file': open(self.output, 'w')
            }

    @staticmethod
    def serialize_list_file(input_file: str) -> List[str]:
        with open(input_file, 'r') as file:
            return [line.strip() for line in file if line.strip()]

    def run(self):
        self.setup_shodan()

        if self.favicon_hashes:
            self.process_favicon_hashes()

        if self.favicon_files or self.file_list:
            self.file_list.extend(self.favicon_files)
            self.process_favicon_files()

        if self.favicon_urls or self.url_list:
            self.url_list.extend(self.favicon_urls)
            self.process_favicon_urls()

        if self.websites or self.web_list:
            self.web_list.extend(self.websites)
            self.process_websites()

        self.lookup_favicons()

        if self.output:
            self.output_file['file'].close()

    def setup_shodan(self):
        if self.key_file:
            self.shodan = Shodan(open(self.key_file, "r").readline().strip())
        elif self.api_key:
            self.shodan = Shodan(self.api_key)
        elif self.use_shodan_cli:
            self.shodan = Shodan(get_api_key())
        else:
            print('[x] Wrong input API key type.')
            exit(1)

    def process_favicon_hashes(self):
        self.iterator.set_description(f"[+] Using Favicon Hash as parameter")
        self.iterator.update(1)
        for fav in self.favicon_hashes:
            self.favicons_list.append({'favhash': fav, '_origin': fav})

    def process_favicon_files(self):
        for fav in self.file_list:
            self.iterator.set_description(f"[+] Processing favicon file {fav}")
            self.iterator.update(1)
            with open(fav, 'rb') as file:
                data = file.read()
                fav_hash = self.calculate_favicon_hash(data)
                self.favicons_list.append({'favhash': fav_hash, 'file': fav, '_origin': fav})

    def process_favicon_urls(self):
        for fav in self.url_list:
            self.iterator.set_description(f"[+] Processing favicon URL {fav}")
            self.iterator.update(1)
            headers = {'User-Agent': self.get_user_agent()}
            response = requests.get(fav, stream=True, headers=headers, verify=False)
            connection_info = self.get_connection_info(response)
            data = response.content
            fav_hash = self.calculate_favicon_hash(data)
            self.favicons_list.append({
                'favhash': fav_hash,
                'url': fav,
                'domain': fav,
                'maskIP': connection_info['ip'],
                'maskISP': connection_info['isp'],
                '_origin': fav
            })

    def process_websites(self):
        for website in self.web_list:
            self.iterator.set_description(f"[+] Processing domain {website}")
            self.iterator.update(1)
            try:
                headers = {'User-Agent': self.get_user_agent()}
                response = requests.get(f"https://{website}", stream=True, headers=headers, verify=False)
                connection_info = self.get_connection_info(response)
                data = self.get_favicon_from_html(f"https://{website}")
                if not isinstance(data, str):
                    fav_hash = self.calculate_favicon_hash(data.content, web_source=True)
                else:
                    fav_hash = "not-found"
            except requests.exceptions.ConnectionError:
                self.iterator.write(f"[x] Connection refused by {website}.")
                if len(self.web_list) == 1:
                    exit(1)
                continue
            self.favicons_list.append({
                'favhash': fav_hash,
                'domain': f"https://{website}",
                'maskIP': connection_info['ip'],
                'maskISP': connection_info['isp'],
                '_origin': website
            })

    def lookup_favicons(self):
        scanned_hashes = {}
        field_names = {'found_ips', 'favhash', 'file', 'url', 'domain', 'maskIP', 'maskISP'}

        if self.output:
            if self.output_file['type'].lower() == 'csv':
                self.output_file['file'].write(','.join(field_names) + '\n')

        self.iterator.reset(total=len(self.favicons_list))
        for fav_data in self.favicons_list:
            self.iterator.set_description(f"[+] Lookup for {fav_data['favhash']}")
            self.iterator.update(1)
            fav_hash = fav_data['favhash']
            if fav_hash in scanned_hashes:
                found_ips = scanned_hashes[fav_hash]
            else:
                found_ips = self.search_shodan(fav_hash)
                scanned_hashes[fav_hash] = found_ips
            fav_data['found_ips'] = found_ips

            if self.show:
                self.iterator.write("-" * 25)
                self.iterator.write(f"[{fav_data['_origin']}]")
                for key, value in fav_data.items():
                    if key != '_origin':
                        self.iterator.write(f"--> {key:<10} :: {value}")

            if self.output:
                if self.output_file['type'].lower() == 'csv':
                    self.output_file['file'].write(','.join(str(fav_data.get(field, '')) for field in field_names) + '\n')
                elif self.output_file['type'].lower() == 'json':
                    self.output_file['file'].write(json.dumps(fav_data) + '\n')
                else:
                    self.iterator.write("[x] Output format not supported, closing.")
                    exit(1)

    def calculate_favicon_hash(self, data: bytes, web_source: Optional[bool] = None) -> int:
        b64data = base64.encodebytes(data).decode() if web_source else base64.encodebytes(data)
        return mmh3.hash(b64data)

    def get_favicon_from_html(self, url: str) -> Optional[str]:
        response = requests.get(url, stream=True, verify=False)
        soup = BeautifulSoup(response.content, 'html.parser')
        icon_link = soup.find('link', rel='icon')
        if icon_link:
            icon_url = icon_link.get("href")
            if not icon_url.startswith("http"):
                icon_url = f"{url}/{icon_url}"
            return requests.get(icon_url, verify=False)
        return "not-found"

    def search_shodan(self, favhash: int) -> str:
        time.sleep(1)
        results = self.shodan.search(f"http.favicon.hash:{favhash}")
        return '|'.join(result['ip_str'] for result in results["matches"])

    def get_connection_info(self, response: requests.Response) -> dict:
        ip = 'not-found'
        isp = 'not-found'
        if response.status_code == 200:
            try:
                ip = response.raw._connection.sock.getpeername()[0]
            except AttributeError:
                try:
                    ip = response.raw._connection.sock.socket.getpeername()[0]
                except AttributeError:
                    pass
            if ip != 'not-found':
                isp = IPWhois(ip).lookup_whois()['nets'][0]['name']
        if ip == 'not-found':
            self.iterator.write(f"[x] Error getting icon for {response.url.split('/')[2]} with status code: {response.status_code}")
        return {'ip': ip, 'isp': isp}

    def get_user_agent(self) -> str:
        try:
            return self.ua.random
        except FakeUserAgentError:
            return "Mozilla/5.0 (X11; Linux x86_64; rv:69.0) Gecko/20100101 Firefox/69.0"


if __name__ == '__main__':
    FavUp(show=True)
