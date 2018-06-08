#!/usr/bin/env python
import re
from string import ascii_lowercase, ascii_uppercase, digits
from tldextract import extract
from collections import defaultdict
import socket

# some regular expressions
domain_regex = re.compile("([a-z0-9][a-z0-9\-]{0,61}[a-z0-9]\.)+[a-z0-9][a-z0-9\-]*[a-z0-9]", re.IGNORECASE)
ipv4_regex = re.compile("[1-2]?[0-9]?[0-9]\.[1-2]?[0-9]?[0-9]\.[1-2]?[0-9]?[0-9]\.[1-2]?[0-9]?[0-9]")

def extract_domain(url):
    try:
        domain = extract(url)
    except Exception:
        raise Exception("Problem while extracting domain".format(url))
    # concatenate domain and tld
    return '.'.join((domain[1],domain[2]))

def extract_domain_details(url):
    try:
        domain_details = extract(url)
    except Exception:
        raise Exception("Problem while extracting domain".format(url))
    return domain_details

def domain_frequencies(url_list):
    freq_dist = defaultdict(int)
    for item in url_list:
        # add domain
        freq_dist[extract_domain(item)] += 1
    freq_dist = [[k,v] for k,v in freq_dist.iteritems()]
    return freq_dist

def valid_ipv4_old(check_str):
    resp = ipv4_regex.search(check_str)
    if resp:
        return resp.group(0)

def valid_domain(check_str):
    resp = domain_regex.search(check_str)
    if resp:
        return resp.group(0)

def valid_ipv4(address):
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:  # no inet_pton here, sorry
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:  # not a valid address
        return False

    return True


if __name__ == '__main__':
    test_url = 'www.google.co.sg'
    print extract_domain(test_url)
    print extract_domain_details(test_url)
    urls = ['www.google.co.in','bing.com','bing.com','gov.in','www.google.co.in']
    print domain_frequencies(urls)
    print valid_ipv4('24.12.32.312')
    print valid_domain('www.google.co')
