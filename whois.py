#!/bin/env python3

import subprocess

def find_whois(domain):
    # Linux 'whois' command wrapper
    # 
    # Executes a whois lookup with the linux command whois.
    # Returncodes from: https://github.com/rfc1036/whois/blob/master/whois.c

    domain = domain.lower().strip()
    d = domain.split('.')
    if d[0] == 'www': d = d[1:]

    # Run command with timeout
    proc = subprocess.Popen(['whois', domain], stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    ans,err = proc.communicate(input)

    if err == 1: raise WhoisError('No Whois Server for this TLD or wrong query syntax') 
    elif err == 2: raise WhoisError('Whois has timed out after ' + str(whois_timeout) + ' seconds. (try again later or try higher timeout)')
    ans = ans.decode('UTF-8')
    return ans


with open('domains.txt') as input:
    with open('out.txt','a') as output:
        for line in input:
            output.write(find_whois(line))