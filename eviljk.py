#!/usr/bin/env python3
import requests
import argparse

import sys
import glob
import validators
import os.path
import socket
import re
import time
import random

from abc import ABC as Abstract, abstractmethod

from urllib.parse import urlparse
from urllib.parse import urlunparse
from urllib.parse import urljoin
from urllib.parse import quote


class EvilScan:

    def __init__(self):
        try:
            self.args, self.parser = self.read_args()
            self.args_verification()
        except ValueError as e:
            raise(e)

        if self.args.dir and not validators.url(self.args.url):
            raise ValueError('[*] Invalid URL')
        else:
            self.url = self.args.url.strip('/')

        if self.args.dir:
            self.mode = "dir"
        elif self.args.subdomain:
            self.mode = "subdomain"
        elif self.args.robots:
            self.mode = "robots"
        else:
            raise ValueError('[*] Not implemented.')

        if self.args.timeout:
            HttpRequest.timeout = self.args.timeout

        if self.args.delay:
            HttpRequest.delay = self.args.delay

        #args_verifaction verified if delayn_min is <= delay_max and inverse too
        if self.args.delay_min and self.args.delay_max:
            HttpRequest.set_delay_min_max(self.args.delay_min, self.args.delay_max)

        


    def scan(self):
        
        if self.mode != 'robots':
            dir_list = glob.glob(self.args.dir_list + "/*") if self.args.dir_list else [self.args.wordlist]
            
            for wordlist in dir_list:
                if self.mode == "dir":
                    scanner = DirectoriesScanner(self.url, wordlist)
                elif self.mode == "subdomain":
                    scanner = SubDomainScanner(self.url, wordlist)
                else:
                    pass
                
                print("Current wordlist: ", wordlist)
                print("-" * 40)
                for dir in scanner.readlines():
                    target, result = scanner.scan(dir)
                    scanner.show_last_result(target, result)
                    scanner.log(target, result)
                    yield(target, result)

                #For directory it will resume the stats order by status code
                #scanner use an abstract class, this method return 'pass' for subdomain and robots
                print()
                scanner.show_logs()

        elif self.mode == 'robots':
            print("I'm a robots.txt scanner!")
            scanner = RobotsTxtScanner(self.url)
            for target, result in scanner.scan():
                scanner.show_last_result(target, result)
                yield(target, result)

        else:
            print("Not implemented")


    def show_results(self):
        pass


    def read_args(self) -> dict and object:
        parser = argparse.ArgumentParser(description='URLBrute - SUB and DIR brute')
        # "http(s)://domain" needed for directory mode, scheme(http || https || ...supported) is required
        parser.add_argument('-u','--url',type=str,required=True, help='Target URL to scan')

        #The modes
        parser.add_argument('-s','--subdomain',action="count", default=0,help='Brute sub domains')
        parser.add_argument('-d','--dir',action="count", default=0,help='Brute dirs')
        parser.add_argument('-r','--robots',action="count", default=0,help='Scan robots.txt')

        #The wordlist, or repertory with a lot of things, be carefull
        parser.add_argument('-w','--wordlist',type=str,default=None, help='Path to wordlist')
        parser.add_argument('-dl','--dir-list', type=str, default=None, help='Directory with wordlists Ex: --dl /usr/share/wordlists')
        
        #general for all modes(-s, -d, -r), timeout, delay or (delay_min and delay_max) (see args_verification and HttpRequest)
        parser.add_argument('--timeout', type=float, default=0, help='Timeout for each request')
        parser.add_argument('--delay', type=int, default=0, help='Delay between each request (In seconds, ex: 0.1)')
        parser.add_argument('--delay-min', type=float, default=0, help='Delay min. between each request (In seconds, ex: 0.1)')
        parser.add_argument('--delay-max', type=float, default=0, help='Delay max. between each request (In seconds, ex: 0.1)')
        args = parser.parse_args()

        return args, parser


    def args_verification(self) -> bool:
        #for some mode, wordlist verifications
        if not self.args.robots:
            #simple wordlist
            if self.args.wordlist and not self.args.dir_list:
                if not os.path.isfile(self.args.wordlist):
                    self.parser.print_help()
                    raise ValueError(f"[*] The wordlist {self.args.wordlist} don't exists")

            #prend un repertoire pour lire toutes les wordlist presentes
            elif self.args.dir_list and not self.args.wordlist:
                if not os.path.isdir(self.args.dir_list):
                    self.parser.print_help()
                    raise ValueError(f"[!] The directory {self.args.dir_list} don't exists")
            else:
                self.parser.print_help()
                raise ValueError(f"[!] The wordlist required for directory/subdomain")


            #un des deux parametres oligatoires
            if not self.args.dir and not self.args.subdomain:
                self.parser.print_help()
                raise ValueError(f"[*] You must choose -d or -s to scan")

            

        #this mode don't need wordlist  
        elif self.args.robots:
            pass

        #not implemented
        else:
            pass
        

        #verification des delays
        if (self.args.delay_min and not self.args.delay_max) \
            or (self.args.delay_max and not self.args.delay_min):
            self.parser.print_help()
            raise ValueError(f"[*] You can't use --delay-min without --delay-max et vice-verca")
        elif self.args.delay_min > self.args.delay_max:
            self.parser.print_help()
            raise ValueError(f"[*] You can't use--delay-max < --delay-min")

        return True

class Scanner(Abstract):
    def __init__(self, url, wordlist: str):
        self.url = url.strip('/')

        tmp = urlparse(self.url)
        self.domain = tmp.netloc
        self.path = tmp.path
        self.scheme = tmp.scheme
        self.query = tmp.query

        self.wordlist = wordlist
        
        
    @abstractmethod
    def readlines(self) -> None:
        pass


    @abstractmethod
    def scan(self, target: str, delay: int = 0):
        pass
    

    @abstractmethod
    def show_last_result(self, target, result):
        pass


    @abstractmethod
    def log(self, target, result):
        pass


    @abstractmethod
    def show_logs(self):
        pass


class RobotsTxtScanner(Scanner):

    def __init__(self, url):
        super().__init__(url, '')
        #We only need a scheme and an host, so i rewrite self.url here
        self.url = urlunparse([self.scheme, self.domain, 'robots.txt', '', '', ''])
        
        self.paths = []
        self.ignored = []
        self.robots_stats = dict()


        self.parse()

        
    def parse(self) -> bool:
        r = HttpRequest.send(self.url, mode="get")
        if not hasattr(r, 'status_code'):
            return False
        
        if r.status_code != requests.codes.ok:
            print(self.url, ": Error", r.status_code)
            return False

        lines = r.text.split("\n")

        for line in lines:
            line = line.lower()
            if line.startswith("disallow:"):
                tmp_path = line.split("disallow:")[1].strip()
                if not re.search("[$*]", tmp_path) and " " not in tmp_path:
                    self.paths.append(tmp_path.strip("/"))
                else:
                    #we keep a log in an array
                    self.ignored.append(tmp_path.strip("/"))
                    continue
               
        return True
        

    def scan(self):
        for path in self.paths:
            url_to_test = urlunparse([self.scheme, self.domain, path, '', '', ''])

            r = HttpRequest.send(url_to_test, mode="head")
            if not hasattr(r, 'status_code'):
                yield  None, None
            else:
                yield url_to_test, r.status_code


    def show_last_result(self, target, result):
        print(f"{target.ljust(40)} {result}")


    def show_logs(self):
       pass


    def log(self, url, status_code):
        pass

    def readlines(self) -> None:
        pass

    

class DirectoriesScanner(Scanner):
    def __init__(self, url, wordlist: str):
        super().__init__(url, wordlist)
        self.directories_stats = dict()
        
        
    def scan(self, directory: str, delay: int = 0) -> (str and int) or (None and None):
        if not directory:
            return None, None

        url_to_test = urlunparse([self.scheme, self.domain, urljoin(self.path + '/', quote(directory)), '', self.query, ''])
        r = HttpRequest.send(url_to_test)

        if not hasattr(r, 'status_code'):
            return None, None

        return url_to_test, r.status_code


    def show_last_result(self, target, result):
        if result and result not in [404, 500]:
            print(f"{target.ljust(40)} {result}")


    def show_logs(self):
        for key in self.directories_stats:
            print("-" * 40)
            print(f"{len(self.directories_stats[key])} urls code {key}")
            print("-" * 40)
            for url in self.directories_stats[key]:
                print(url)
            print()


    def log(self, url, status_code):
        if (not url or not status_code) or status_code in [404]:
            return None
        elif str(status_code) in self.directories_stats:
            self.directories_stats[str(status_code)].append(url)
        else:
            self.directories_stats.update({str(status_code): [url]})

    def readlines(self) -> None:
        with open(self.wordlist, 'r') as pf1:
            for line in pf1.readlines():
                yield(line.strip())

 
class SubDomainScanner(Scanner):
    def __init__(self, url, wordlist: str):
        super().__init__(url, wordlist)
        #en cas d'un scan subdomain dans le scheme http, urlparse retourne le domaine dans path!
        #alors on inverse
        if not self.domain and self.path:
            self.domain, self.path = self.path , self.domain

        self.subdomains_stats = dict()

    def scan(self, subdomain: str, delay: int = 0) -> (str and list) or (None and None):
        if not subdomain:
            return None, []
        
        #mise en forme du sous domain
        subdomain_clean = ".".join([re.sub(r'[^a-zA-Z0-9\.]+', '-', subdomain).lower().strip(), self.domain])        
        
        try:
            result = socket.gethostbyname_ex(subdomain_clean)
        except Exception:
            return None, []
        else:
            return subdomain_clean, result[2]


    def show_last_result(self, target, result):
        for ip in result:
            print(target.ljust(40), ip.ljust(15))
        

    def show_logs(self):
        pass


    def log(self, subdomain, ip_list):
        pass


    def readlines(self) -> None:
        with open(self.wordlist, 'r') as pf1:
            for line in pf1.readlines():
                yield(line.strip())


class HttpRequest:
    timeout: int = 10 

    #if delay_min and delay_max exists, it will be re-calculated at every call of HttpRequest.send(url).
    delay: float =  0

    #you need to verify if delay_min < delay_max and vice-versa
    delay_min: float = 0
    delay_max: float = 0

    @staticmethod
    def set_delay_min_max(delay_min: float, delay_max: float):
        HttpRequest.delay_min = delay_min
        HttpRequest.delay_max = delay_max
        
    @staticmethod
    def send(url: str, mode: str = 'head') -> requests:
        headers = {'User-agent' : 'Mozilla/5.0 (X11; Linux x86_64; rv:136.0) Gecko/20100101 Firefox/136.0'}

        if HttpRequest.delay_min and HttpRequest.delay_max:
            HttpRequest.delay = random.uniform(HttpRequest.delay_min, HttpRequest.delay_max)
            print("Delay: ", HttpRequest.delay)
            time.sleep(HttpRequest.delay)
        
        try:

            if mode == 'head':
                r = requests.head(url, allow_redirects=True, timeout=HttpRequest.timeout, headers=headers)
            elif mode == 'get':
                r = requests.get(url, allow_redirects=True, timeout=HttpRequest.timeout, headers=headers)
            else:
                return None

            return r

        except requests.exceptions.MissingSchema as e:
            print(e)
            return None

        except requests.exceptions.Timeout as e:
            print(e)
            return None

        except requests.exceptions.TooManyRedirects as e:
            print(e)
            return None
            
        except requests.RequestException as e:
            print(e)
            return None

        except Exception as e:
            print("This is a suck.my.dick or an urllib.error: ", e)
            return None


if __name__ == '__main__':
    try:
        evil_scanner = EvilScan()
    except ValueError as e:
        sys.exit(e)

    #you can do what you want with target and result value returned by the scan() method
    for target, result in evil_scanner.scan():
        pass


   