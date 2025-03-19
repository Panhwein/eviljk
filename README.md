zeubx1 written this.
You need to install python-validators.

So you can scan directories, files or subdomains.


usage: eviljk.py [-h] -u URL [-s] [-d] [-r] [-w WORDLIST] [-dl DIR_LIST] [--timeout TIMEOUT] [--delay DELAY]
                 [--delay-min DELAY_MIN] [--delay-max DELAY_MAX]

options:
  -h, --help            show this help message and exit
  -u, --url URL         Target URL to scan
  -s, --subdomain       Brute sub domains
  -d, --dir             Brute dirs
  -r, --robots          Scan robots.txt
  -w, --wordlist WORDLIST
                        Path to wordlist
  -dl, --dir-list DIR_LIST
                        Directory with wordlists Ex: --dl /usr/share/wordlists
  --timeout TIMEOUT     Timeout for each request
  --delay DELAY         Delay between each request (In seconds, ex: 0.1)
  --delay-min DELAY_MIN
                        Delay min. between each request (In seconds, ex: 0.1)
  --delay-max DELAY_MAX
                        Delay max. between each request (In seconds, ex: 0.1)
➜  eviljk git:(210751b) ✗ 

