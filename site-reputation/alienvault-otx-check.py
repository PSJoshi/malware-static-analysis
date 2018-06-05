#!/usr/bin/env python
import sys
import logging
import requests
import argparse
import json
from OTXv2 import OTXv2
from pprint import pprint 

"""
This script uses AlienVault API to get indicators of compromise (IOC) - ip, domains, hashes etc.
These IOC can be applied in organization environment to get rid of malicious activities.
Links of interest:
https://github.com/AlienVault-OTX/ApiV2
https://github.com/AlienVault-OTX/OTX-Python-SDK/blob/master/howto_use_python_otx_api.ipynb
https://github.com/Neo23x0/signature-base/blob/master/threatintel/get-otx-iocs.py
https://github.com/Neo23x0/signature-base/tree/master/threatintel

Sample usage cases as per https://github.com/AlienVault-OTX/ApiV2:

    https://www.threatcrowd.org/searchApi/v2/email/report/?email=william19770319@yahoo.com
    https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=aoldaily.com
    https://www.threatcrowd.org/searchApi/v2/ip/report/?ip=188.40.75.132
    https://www.threatcrowd.org/searchApi/v2/antivirus/report/?antivirus=plugx
    https://www.threatcrowd.org/searchApi/v2/file/report/?resource=ec8c89aa5e521572c74e2dd02a4daf78

"""
# setup logging
logging.basicConfig(stream=sys.stdout,level = logging.DEBUG)
logger = logging.getLogger(__name__)

# OTX base urls
otx_base_url_domain = 'https://www.threatcrowd.org/searchApi/v2/domain/report/?'
otx_base_url_ip = 'https://www.threatcrowd.org/searchApi/v2/ip/report/?'
otx_base_url_hash = 'https://www.threatcrowd.org/searchApi/v2/file/report/?'
otx_base_url_email = 'https://www.threatcrowd.org/searchApi/v2/email/report/?'

def cmd_arguments():

    try:
        parser = argparse.ArgumentParser("This script checks domain reputation using Alienvault threat exchange service.")

        parser.add_argument('--domain', required=False, help='Please specify domain name!',dest='domain')
        parser.add_argument('--ip', required=False, help='Please specify ip!',dest='ip')
        parser.add_argument('--email', required=False, help='Please specify email!',dest='email')
        parser.add_argument('--hash', required=False, help='Please specify domain name!',dest='hash')

        parser.add_argument('--proxy-host', required=False, help='Please specify proxy host',dest='proxy_host')
        parser.add_argument('--proxy-port', required=False, help='Please specify proxy port',dest='proxy_port')
        parser.add_argument('--proxy-user', required=False, help='Please specify proxy user',dest='proxy_user')
        parser.add_argument('--proxy-password', required=False, help='Please specify proxy password',dest='proxy_password')

        args = parser.parse_args()
        if args.domain == None and args.ip == None and args.email == None and args.hash == None:
            logger.error("You have to specify at least one argument - domain/ip/email/file hash for finding out its threat reputation.")
            sys.exit(1) 
        return args
    except Exception as exc:
        logger.error("Error while getting command line arguments - %s" %exc.message,exc_info=True)


if __name__ == "__main__":
    try:
        cmd_args = cmd_arguments()
        proxy_dict = {
                      'http':'http://{}:{}@{}:{}'.format(cmd_args.proxy_user,cmd_args.proxy_password,cmd_args.proxy_host,cmd_args.proxy_port),
                      'https':'http://{}:{}@{}:{}'.format(cmd_args.proxy_user,cmd_args.proxy_password,cmd_args.proxy_host,cmd_args.proxy_port),
                     }  
        logger.info("Proxies - {}".format(proxy_dict))

        ### Domain information ###
        if cmd_args.domain:
            cmd_args_domain = str(cmd_args.domain).replace("https://","").replace("http://","").replace("www","")
            otx_url = otx_base_url_domain + 'domain={}'.format(cmd_args_domain) 
            response = requests.get(otx_url, proxies=proxy_dict, verify=False)
            if response.text:
                json_response = json.loads(response.text)
                pprint(json_response)   

        ### IP information ###
        if cmd_args.ip:
            otx_url = otx_base_url_ip + 'ip={}'.format(cmd_args.ip) 
            response = requests.get(otx_url, proxies=proxy_dict, verify=False)
            if response.text:
                json_response = json.loads(response.text)
                pprint(json_response) 
  
        ### file hash information ###
        if cmd_args.hash:
            otx_url = otx_base_url_hash + 'resource={}'.format(cmd_args.hash) 
            response = requests.get(otx_url, proxies=proxy_dict, verify=False)
            if response.text:
                json_response = json.loads(response.text)
                pprint(json_response) 

        ### email information ###
        if cmd_args.email:
            otx_url = otx_base_url_email + 'email={}'.format(cmd_args.email) 
            response = requests.get(otx_url, proxies=proxy_dict, verify=False)
            if response.text:
                json_response = json.loads(response.text)
                pprint(json_response) 

    except Exception as exc:
        logger.error("Error while getting site reputation information - %s" %exc.message,exc_info=True)

