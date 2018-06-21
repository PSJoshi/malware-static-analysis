#!/usr/bin/env python
import sys
import os
import requests
from bs4 import BeautifulSoup
import argparse
import logging
import yaml
from pprint import pprint
import untangle
from StringIO import StringIO
from urlparse import urlparse
import validators
"""
Details of URLVoid API service - http://www.urlvoid.com/api/
IPVoid service - http://www.ipvoid.com/ip-blacklist-check/ and
Make a POST request using ip:{ip} as parameter
"""
# setup logging
logging.basicConfig(stream=sys.stdout,level = logging.DEBUG)
logger = logging.getLogger(__name__)

urlvoid_base_url = 'http://api.urlvoid.com/'
ipvoid_url = 'http://www.ipvoid.com/ip-blacklist-check/'
def yaml_config(yaml_file):
    try:
        with open(yaml_file, 'r') as f:
            configuration_data = yaml.load(f)
        return configuration_data

    except Exception as exc:
        logger.error("Error while reading yaml configuration file - %s" %e.message,exc_info=True)    
    return None

def url_parameters(url):
    # instead of urlparse, better to use tldextract and get domain,subdomain details!
    parsed_response = urlparse(url)
    return parsed_response.scheme, parsed_response.netloc

def Isurl(check_url):
    try:
        return validators.url(check_url)
    except Exception:
        return False

def IsIP(check_ip):
    try:
        return validators.ipv4(check_ip)
    except Exception:
        return False

def cmd_arguments():

    try:
        parser = argparse.ArgumentParser("This script uses url/ip repuation services like urlvoid.com, ipvoid.com on the internet to check if the ip/domain is malicious or not.")
        parser.add_argument('--config', required=True, help='Please specify configuration file',dest='config_file')
        parser.add_argument('--url', required=False, help='Please specify url address',dest='url')
        parser.add_argument('--ip', required=False, help='Please specify ip address',dest='ip')
        args = parser.parse_args()
        return args
    except Exception as exc:
        logger.error("Error while getting command line arguments - %s" %exc.message,exc_info=True)

def urlvoid_status(domain,api_info):
    remaining_queries = None
    try:
        response = None
        #http://api.urlvoid.com/{identifier}/{key}/stats/remained/
        url = urlvoid_base_url + os.path.join(os.path.sep,  
                           api_info['settings']['identifier'],
                           api_info['settings']['key'],
                           'stats','remained')
        
        logger.debug("Urlvoid API status url: %s"%url)
        response = requests.get(url)
        parsed_response = untangle.parse(StringIO(response.text))
        logger.info("Urlvoid API - remaining domain queries (per day) - %s"
                    % parsed_response.response.queriesRemained.cdata)
        remaining_queries = parsed_response.response.queriesRemained.cdata
        
    except Exception,e:
        logger.error("Error while getting status information from urlvoid portal - %s"
                     %e.message,exc_info=True) 
    return remaining_queries

def urlvoid_report(domain,api_info):
    cnt = 0
    try:
        response = None
        #http://api.urlvoid.com/{identifier}/{key}/host/{domain}/
        url = urlvoid_base_url + os.path.join(os.path.sep, 
                           api_info['settings']['identifier'],
                           api_info['settings']['key'],
                           'host', domain)
        
        logger.debug("Urlvoid API url: %s"%url)

        response = requests.get(url)
        # convert requests response to file stream 
        parsed_response = untangle.parse(StringIO(response.text))

        # No of blacklists that detect domain as malicious in URLVoid database
        try:
            cnt = parsed_response.response.detections.count
        except Exception:
            cnt = 0
    except Exception,e:
        logger.error("Error while getting domain information from urlvoid portal - %s"
                     %e.message,exc_info=True) 
    return cnt

def ipvoid_query(ip):
    try:
        response = requests.post(ipvoid_url,data={'ip':'%s'%ip})
        if response:
            results = ipvoid_results(response.text,ip)
            if len(results)>=1 :
                return dict(zip(['blacklist_status', 'analysis_date', 'ip_address', 'rdns', 'asn', 'country'],results[1:]))
    except Exception,e:
        logger.error("Error while getting ip information from IPVoid portal - %s"
                     %e.message,exc_info=True)
    return None
 
def ipvoid_results(html_content,ip):
    try:
        soup_instance = BeautifulSoup(html_content, "html.parser")
        data = soup_instance.find("table")
        if data:
            blacklist_status = data.find("td", text="Blacklist Status")
            result_blacklist_status = blacklist_status.findNext("td").text
            analysis_date = data.find("td", text="Analysis Date")
            result_analysis_date = analysis_date.findNext("td").text
            ip_addr = data.find("td", text="IP Address")
            result_ip_address = ip_addr.findNext("td").strong.text
            rdns_data = data.find("td", text="Reverse DNS")
            result_rdns = rdns_data.findNext("td").text
            asn_data = data.find("td", text="ASN")
            result_asn = asn_data.findNext("td").text
            country_data = data.find("td", text="Country Code")
            result_country = country_data.findNext("td").text
            return ['True',result_blacklist_status, result_analysis_date, 
                  result_ip_address, result_rdns, result_asn, result_country]
        else:
            logger.info("No results found on ipvoid portal for ip - %s!" %ip)
    except Exception as e:
        print("Error parsing ipvoid: %s" % e)
    return ['False']


if __name__ == "__main__":
    try:
        cmd_args = cmd_arguments()
        if cmd_args:

            # read yaml configuration
            if os.path.isfile(cmd_args.config_file):
                config = yaml_config(cmd_args.config_file)
                logger.debug("%s" %pprint(config))

                # check if key and identity are valid
                if not (config['settings']['identifier'] 
                        and config['settings']['key']):
                    logger.error("API keys and identity for Urlvoid API service" 
                                 " could not be found in the configuration file.."
                                 " Quitting..")
                # check if ip is valid
                if IsIP(cmd_args.ip):
                    logger.info("IP %s will be checked using IPVoid blacklist service."% cmd_args.ip)
                    ip_results = ipvoid_query(cmd_args.ip)
                    logger.info("IP information as found on IPVoid blacklist service:%s" %ip_results)

                # check if url is valid  
                if Isurl(cmd_args.url): 
                    _,domain = url_parameters(cmd_args.url)
                    logger.info("Domain %s will be checked using URLvoid API domain service."%domain) 
                    remaining_queries = urlvoid_status(domain,config) 
                    if remaining_queries>0:
                        blacklist_cnt = urlvoid_report(domain,config)
                        if blacklist_cnt > 0:
                            logger.info("As per URLVoid domain reputation service," 
                            " the domain %s is blacklisted in %s lists."%(domain,blacklist_cnt))
                        else:
                            logger.info("As per URLVoid domain reputation service," 
                            " the domain %s is not blacklisted."%(domain)) 

    except Exception as e:
        logger.error("Error while getting ip/domain information - %s" %e.message,exc_info=True)
