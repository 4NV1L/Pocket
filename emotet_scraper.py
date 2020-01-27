#!/bin/env python3
#Emotet IOC webscraper 
#Source https://paste.cryptolaemus.com/
# Production url - https://paste.cryptolaemus.com/emotet/{now_time_path}/emotet-malware-IoCs_{now_time_file}.html
# Test url - https://paste.cryptolaemus.com/emotet/2019/02/15/emotet-malware-IoCs_02-15-19.html


import datetime # emotet IOC feed updates everyother day, somtimes daily. Datetime will be used to manipuate the time on the url
import requests # used to manipulate the requests & url 
import re       # Enabled Regex Matching
import logging
from bs4 import BeautifulSoup # HTML Parsing

now_time_path = datetime.datetime.now().strftime("%Y/%m/%d") # Matching time on url setting to now
now_time_file = datetime.datetime.now().strftime("%m-%d-%y") # Matching time on the file setting now 

Banner = '''

Emotet Cryptolaemus Scraper

    Please Select your IOCs
    - Domains
    - Hashes
    - IPs

'''
print(Banner)

DOMAINS = 'Domains'
HASHES = 'Hashes'
IPADDRESS = 'IPs'
userinfo = ""

url = (f'https://paste.cryptolaemus.com/emotet/{now_time_path}/emotet-malware-IoCs_{now_time_file}.html')
page = requests.get(url) 
status = page.status_code           # Storing Page status code
content = page.text                 # Storing Page Content

if status == int(404): # Error handling when the page you touch doesn't have a current date. 
    print('''
    
    There are no new Emotet IOCs on paste.cryptolaemus.com try back later...
    
    ''')
else:
    userinfo = input('Welcome to Emotet IOC Scraper, What IOC would you like? ') # Using userinfo to take value from user input 

# If condition for the hashes on user input

if userinfo == HASHES:
    try:
        print('Gathering your Hashes...')
        # soup = BeautifulSoup(content, 'html.parser') Commenting out due to redundancy
        # page_1 = soup.find_all('code')
        hashes = re.findall(r"[a-fA-F0-9]{64}", page.text)
        with open(f'emotet_Hashes.csv','w') as f:
                for row in hashes:
                    f.write(f'{row}\n')
        print('Success!!')
    except KeyboardInterrupt as e:
        msg = "Received KeyboardInterrupt - shutting down"
else:
    print('Excluding Hashes')

# If condition for the Domains on user input 

if userinfo == DOMAINS:
    try:
        print('Gathering your Domains...')
        # soup = BeautifulSoup(content, 'html.parser') Commenting out due to redundancy
        # page_1 = soup.find_all('code')
        url_path = list(map(str.strip, re.findall(r"h..p://.*\n",page.text)))
        with open(f'emotet_Domains.csv','w') as f:
                 for row in url_path:
                    f.write(f'{row}\n')
        print('Success!!')
    except KeyboardInterrupt as e:
        msg = "Received KeyboardInterrupt - shutting down"
else:
    print('Excluding Domains')

# If condition for the IP Addresses on user input 

if userinfo == IPADDRESS:
    try:
        print('Gathering your IP Addresses...')
        # soup = BeautifulSoup(content, 'html.parser') Commenting out due to redundancy
        # page_1 = soup.find_all('code')
        ip_address = re.findall(r"\d\d?\d?\.\d\d?\d?\.\d\d?\d?\.\d\d?\d?",page.text)
        with open(f'emotet_ip_addresses.','w') as f:
                 for row in ip_address:
                    f.write(f'{row}\n')
        print('Success!!')
    except KeyboardInterrupt as e:
        msg = "Received KeyboardInterrupt - shutting down"
else:
    print('Excluding IP Addresses')
