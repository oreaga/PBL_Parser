#!/usr/bin/env python

import os
import sys
import re
import datetime
import wget
import requests
from bs4 import BeautifulSoup


class PBLCrawler():

    """
        Class for crawling public blacklists and aggregating a list of known malicious domains
    """

    def __init__(self):
        self.dir = '/fs/sdsatumd/bl_domains/public_dumps/'
        self.today = datetime.date.today()

    def crawl(self):
        self.crawl_abuse_ssl()
        self.crawl_abuse_rw()
        self.crawl_abuse_bl()
        self.crawl_malwaredomainlist()
        self.crawl_hphost()
        self.crawl_sans()
        self.crawl_sagadc()
        self.crawl_malcode()

    def crawl_hphost(self):
        print 'Crawling hphost...'
        files = ["ad_servers.txt", "emd.txt", "exp.txt", "fsa.txt", "grm.txt", "hfs.txt", "hjk.txt", "mmt.txt", "pha.txt", "psh.txt", "pup.txt", "wrz.txt"]
        classification = ["ad/tracking servers", "malware sites", "exploit sites", "fraud sites", "spam", "sites spamming the hpHosts forums", "hijack sites",\
                          "misleading marketing", "illegal pharmacy sites", "phishing sites", "PUP sites", "warez/piracy sites"]

        hphost_output = os.path.join(self.dir, "hphost")
        if not os.path.exists(hphost_output):
            os.makedirs(hphost_output)

        for f in files:
            url = "https://hosts-file.net/" + f
            wget.download(url, out=hphost_output)

        for i in range(len(files)):
            filename = files[i]
            classname = classification[i]
            fl = open(os.path.join(hphost_output, filename), 'r')
            lines = fl.readlines()
            fl.close()

            with open(os.path.join(hphost_output, self.today.isoformat() +  '.txt'), 'a') as fl:
                for line in lines:
                    fields = line.strip().split('\t')
                    if len(fields) < 2:
                        continue
                    fl.write(self.today.isoformat() + ',' + fields[1].strip(' ') + ',' + classname + '\n')
            os.remove(os.path.join(hphost_output, filename))


    def crawl_sans(self):
        print 'Crawling sans...'
        files = ["suspiciousdomains_Low.txt", "suspiciousdomains_Medium.txt", "suspiciousdomains_High.txt"]

        sans_output = os.path.join(self.dir, "sans")
        if not os.path.exists(sans_output):
            os.makedirs(sans_output)

        for f in files:
            url = "https://isc.sans.edu/feeds/" + f
            wget.download(url, out= sans_output)

        for i in range(len(files)):
            filename = files[i]
            classname = ''
            fl = open(os.path.join(sans_output, filename), 'r')
            lines = fl.readlines()
            fl.close()

            with open(os.path.join(sans_output, self.today.isoformat() +  '.txt'), 'a') as fl:
                for line in lines:
                    if line[0] == '#':
                        continue
                    domain = line.strip("\n")
                    if domain == "Site":
                        continue
                    fl.write(self.today.isoformat() + ',' + domain.strip(' ') + ',' + classname + '\n')
            os.remove(os.path.join(sans_output, filename))

    def crawl_abuse_ssl(self):
        print('Crawling abuse-ch-ssl')
        site = requests.get('https://sslbl.abuse.ch/')k
        tree = BeautifulSoup(site.text, 'lxml')


        name_pos, h_index = self.get_table_index(tree, 'Common Name')
        date_pos, h_index = self.get_table_index(tree, 'Listing date')
        reason_pos, h_index = self.get_table_index(tree, 'Listing reason')

        with open(os.path.join(self.dir, 'abuse-ch-ssl', self.today.isoformat() + '.txt'), 'w') as fl:
            i = 0

            for el in tree.find_all('td'):
                if i % h_index == date_pos:
                    text = str(el.text)
                    match = re.match('\d{4}\-\d{2}\-\d{2}', text)
                elif i % h_index == name_pos:
                    name_text = str(el.text)
                elif i % h_index == reason_pos:
                    reason_text = str(el.text)

                    domain = re.search('((.*\.)+.+)\/*', name_text)
                    if domain is not None:
                        fl.write(match.group(0) + ',')
                        fl.write(domain.group(1) + ',')
                        fl.write(reason_text + '\n')

                i += 1


    # Returns the number of pages currently used by the abuse-ch ransomware tracker
    def num_pages(self):
        url_base = 'http://ransomwaretracker.abuse.ch/tracker/'
        headers = {'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:54.0) Gecko/20100101 Firefox/54.0',
                   'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
                   }
        resp = requests.get(url_base, headers=headers)
        tree = BeautifulSoup(resp.text, 'lxml')
        num = 0

        for cent in tree.find_all('center'):
            for page in cent.find_all('a'):
                num = num + 1

        return num

    def crawl_abuse_rw(self):
        print('Crawling abuse-ch-rw')
        url_base = 'http://ransomwaretracker.abuse.ch/tracker/'
        urls = ['']
        headers = {'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:54.0) Gecko/20100101 Firefox/54.0',
                   'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
                   }
        num_pages = self.num_pages()

        for i in range(2, num_pages):
            urls.append('page/' + str(i) + '/')

        for page in urls:
            url = url_base + page
            print(url)
            resp = requests.get(url_base, headers=headers)
            tree = BeautifulSoup(resp.text, 'lxml')
            date_pos, h_index = self.get_table_index(tree, 'Date')
            malware_pos, h_index = self.get_table_index(tree, 'Malware')
            name_pos, h_index = self.get_table_index(tree, 'Host')

            with open(os.path.join(self.dir, 'abuse-ch-rw', self.today.isoformat() + '.txt'), 'a') as fl:
                for row in tree.find_all('tr'):
                    i = 0
                    for el in row.find_all('td'):
                        if i == date_pos:
                            match = re.match('\d{4}\-\d{2}\-\d{2}', str(el.text))

                        elif i == malware_pos:
                            child = el.find('span')
                            malware_text = str(child.text)

                        if i == name_pos:
                            child = el.find('a')
                            text = str(child.text)
                            fl.write(match.group(0) + ',')
                            fl.write(text + ',')
                            fl.write(malware_text + '\n')

                        i += 1

    # Crawls the abuse-ch blocklists for domains
    def crawl_abuse_bl(self):
        print('Crawling abuse-ch-bl')
        d_url = 'http://ransomwaretracker.abuse.ch/downloads/RW_DOMBL.txt'  # Domain blocklist
        u_url = 'http://ransomwaretracker.abuse.ch/downloads/RW_URLBL.txt'  # URL blocklist
        past_header = False
        count = 0

        # Crawl the domain blocklist
        resp = requests.get(d_url)
        contents = [x.strip() for x in resp.iter_lines()]
        print(d_url)

        with open(os.path.join(self.dir, 'abuse-ch-bl', self.today.isoformat() +  '.txt'), 'w') as fl:
            for line in contents[:-1]:
                if past_header is True:
                    fl.write('null,' + line + '\n')
                elif line == '##########################################################################':
                    if count == 1:
                        past_header = True
                    else:
                        count += 1

        # Crawl the URL blocklist
        resp = requests.get(u_url)
        contents = [x.strip() for x in resp.iter_lines()]
        print(u_url)
        count = 0
        past_header = False

        with open(os.path.join(self.dir, 'abuse-ch-bl', self.today.isoformat() +  '.txt'), 'a') as fl:
            for line in [x.strip('http://') for x in contents[:-1]]:
                if past_header is True:
                    fl.write('null' + ',' + line + ',ransomware\n')
                elif line == '##########################################################################':
                    if count == 1:
                        past_header = True
                    else:
                        count += 1

    def crawl_malwaredomainlist(self):
        print 'Crawling malwaredomainlist...'
        os.chdir('/fs/sdsatumd/bl_domains/public_dumps/malwaredomainlist')
        wget.download('http://www.malwaredomainlist.com/mdlcsv.php')

        fl = open('export.csv', 'r')
        lines = fl.readlines()
        fl.close()

        with open(os.path.join(self.dir, 'malwaredomainlist', self.today.isoformat() +  '.txt'), 'w') as fl:
            for line in lines:
                fields = line.strip().split(',')
                try:
                    fl.write('{}-{}-{}'.format(fields[0][1:5], fields[0][6:8], fields[0][9:11]) + ',' + fields[1].strip('\"') + ',' + fields[4].strip('\"') + '\n')
                except IndexError:
                    print('Bad line')

        os.remove('export.csv')

    def crawl_malcode(self):
        print 'Crawling malcode...'
        page = lib2.urlopen('http://malc0de.com/bl/BOOT')
        contents = page.readlines()

        i = 0

        with open(os.path.join(self.dir, 'malcode', self.today + '.txt'), 'w') as fl:
            for line in contents:
                if 'PRIMARY' in line:
                    fields = line.split()
                    fl.write('null,' + fields[1] + '\n')

    def crawl_sagadc(self):
        print 'Crawling sagadc...'
        page = lib2.urlopen('http://dns-bh.sagadc.org/domains.txt')
        contents = page.readlines()

        with open(os.path.join(self.dir, 'sagadc', self.today + '.txt'), 'w') as fl:
            for line in contents:
                if line[0] != '#':
                    fields = line.strip().split()
                    fl.write('{},{},{}\n'.format(fields[-1], fields[0], fields[1]))


    # Takes string as input and returns a set of domains already retrieved from the site
    def get_domains(self, file):
        domains = set()

        with open(self.dir + file, 'r') as fl:
            for line in [x.rstrip('\n').split(',')[1] for x in fl.readlines()]:
                domains.add(line)

        return domains

    # Takes an etree and a header string and returns the index of the column for that header
    def get_table_index(self, tree, header):
        h_index = 0
        name_pos = None

        for el in tree.find_all('th'):
            if header in str(el.text):
                name_pos = h_index

            h_index = h_index + 1

        if name_pos is None:
            print('Could not find header name in list of headers')
            sys.exit(1)
        elif h_index is 0:
            print('Site had no table headers')
            sys.exit(1)

        return name_pos, h_index

if __name__ == '__main__':
    crawler = PBLCrawler()

    crawler.crawl()
