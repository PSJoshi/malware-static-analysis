#!/usr/bin/env python
import sys
import logging
import requests
import argparse
import json
from bs4 import BeautifulSoup
#import shodan

"""
This script uses Shodan API to determine site reputation and vulnerabilities if present.

"""

# setup logging
logging.basicConfig(stream=sys.stdout,level = logging.DEBUG)
logger = logging.getLogger(__name__)

base_url = 'https://api.shodan.io'

def api_information(api_key,proxy_dict=None):
    json_response = None
    try:
        url = base_url + '/api-info?key={}'.format(api_key)
        response = requests.get(url,proxies=proxy_dict,verify=False)
        json_response = response.json()
    except Exception,exc:
        logger.error("Error while getting Shodan API status information - %s" %exc.message,exc_info=True)
    return json_response

def ip_information(api_key=None,proxy_dict=None,test_ip=None):
    json_response = None
    try:
        url = base_url + '/shodan/host/{}?key={}'.format(test_ip,api_key)
        response = requests.get(url,proxies=proxy_dict,verify=False)
        json_response = response.json()
    except Exception,exc:
        logger.error("Error while getting IP information from Shodan API - %s" %exc.message,exc_info=True)

    return json_response

def shodan_scanning_ports(api_key,proxy_dict=None):
    json_response = None
    try:
        url = base_url + '/shodan/ports?key={}'.format(api_key)
        response = requests.get(url,proxies=proxy_dict,verify=False)
        json_response = response.json()
    except Exception,exc:
        logger.error("Error while getting IP information from Shodan API - %s" %exc.message,exc_info=True)

    return json_response

def is_vpn(api_key=None,proxy_dict=None, test_ip=None):
    json_response = None
    try:
        url = base_url + '/shodan/host/{}?key={}'.format(test_ip,api_key)
        response = requests.get(url,proxies=proxy_dict,verify=False)
        json_response = response.json()
        for banner in json_response['data']:
            if banner['port'] in [500, 4500]:
                return True
    except Exception,exc:
        logger.error("Error while detecting VPN from Shodan API - %s" %exc.message,exc_info=True)
    return False    

def http_headers(api_key,proxy_dict=None):
    json_response = None
    try:
        url = base_url + '/tools/httpheaders?key={}'.format(api_key)
        response = requests.get(url,proxies=proxy_dict,verify=False)
        json_response = response.json()

    except Exception,exc:
        logger.error("Error while getting client HTTP headers information from Shodan API - %s" %exc.message,exc_info=True)

    return json_response


   
#def is_vpn_shodan_module(api_key,proxy_dict, test_ip):
#    # this function uses shodan python module. 
#    try:
#        host = api.host(test_ip)
#        for banner in host['data']:
#            if banner['port'] in [500, 4500]:
#                return True
#        return False
#    except Exception,exc:
#        logger.error("Error while detecting VPN from Shodan API - %s" %exc.message,exc_info=True)

def cmd_arguments():

    try:
        parser = argparse.ArgumentParser("This script uses Shodan API to check various attributes of site like reputation, open ports etc.")

        parser.add_argument('--domain', required=False, help='Please specify domain name!',dest='domain')
        parser.add_argument('--ip', required=False, help='Please specify domain name!',dest='ip')
        parser.add_argument('--api-key', required=True, help='Please specify domain name!',dest='api_key')
        parser.add_argument('--proxy-host', required=False, help='Please specify proxy host',dest='proxy_host')
        parser.add_argument('--proxy-port', required=False, help='Please specify proxy port',dest='proxy_port')
        parser.add_argument('--proxy-user', required=False, help='Please specify proxy user',dest='proxy_user')
        parser.add_argument('--proxy-password', required=False, help='Please specify proxy password',dest='proxy_password')
        args = parser.parse_args()
        return args
    except Exception as exc:
        logger.error("Error while getting command line arguments - %s" %exc.message,exc_info=True)


if __name__ == "__main__":
    try:
        cmd_args = cmd_arguments()
        if cmd_args.ip == None and cmd_args.domain == None:
            logger.info("Kindly enter either the IP or domain name to get relevant results!")   

        if cmd_args.ip:
            proxy_dict = {
                      'http':'http://{}:{}@{}:{}'.format(cmd_args.proxy_user,cmd_args.proxy_password,cmd_args.proxy_host,cmd_args.proxy_port),
                      'https':'http://{}:{}@{}:{}'.format(cmd_args.proxy_user,cmd_args.proxy_password,cmd_args.proxy_host,cmd_args.proxy_port),
                     }  
            logger.info("Proxies - {}".format(proxy_dict))

            ### API information
            logger.info("Getting Shodan API status information.")
            api_info = api_information(cmd_args.api_key,proxy_dict) 
            logger.info("Shodan API status information:\n{}".format(api_info))
            logger.info("The job of getting Shodan API status information is over")
  
            ### HTTP client headers information
            logger.info("Getting HTTP client headers using Shodan API.")
            http_client_headers = http_headers(cmd_args.api_key,proxy_dict) 
            logger.info("HTTP client headers:\n{}".format(http_client_headers))
            logger.info("The job of getting HTTP client headers using Shodan API is over.")

            ### IP information 
            logger.info("Getting IP information from Shodan engine..")
            ip_info = ip_information(cmd_args.api_key,proxy_dict,cmd_args.ip)
            if ip_info:
                logger.info("IP information as reported by Shodan engine:\n {}".format(ip_info))
            logger.info("The job of getting IP information from Shodan engine is over.")
            
            ### Scanning ports used by Shodan engine 
            logger.info("Checking scan ports used by Shodan engine..")
            scanning_ports = shodan_scanning_ports(cmd_args.api_key,proxy_dict)
            if scanning_ports:  
                logger.info("Scanning ports used by Shodan are:{}".format(','.join([str(x) for x in scanning_ports])))
            logger.info("Checking of scan ports used by Shodan engine is over.")

            #### check if VPN ports are open
            logger.info("Checking if VPN ports are open or not for site {} using Shodan engine..".format(cmd_args.ip))
            vpn_result = is_vpn(cmd_args.api_key,proxy_dict,cmd_args.ip)
            if vpn_result:  
                logger.info("As reported by Shodan engine, VPN ports are open. Please check if it is OK.")
            else:
                logger.info("No VPN ports are open for ip {}".format(cmd_args.ip))    
            logger.info("Checking of VPN ports using Shodan engine is over.")


    except Exception as exc:
        logger.error("Error while getting Shodan site reputation information - %s" %exc.message,exc_info=True)
