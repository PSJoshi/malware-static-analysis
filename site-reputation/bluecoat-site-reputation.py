#!/usr/bin/env python
import sys
import logging
import requests
import argparse
import json
from bs4 import BeautifulSoup

"""
This script uses Bluecoat datasbase to get website reputation.
Site reputation categories -  https://sitereview.bluecoat.com/rest/categoryDetails?id=$NUM$
To-do:
Possible to use IBM X-force check API
https://exchange.xforce.ibmcloud.com/url/
https://api.xforce.ibmcloud.com/url/

"""

# setup logging
logging.basicConfig(stream=sys.stdout,level = logging.DEBUG)
logger = logging.getLogger(__name__)

url = 'https://sitereview.bluecoat.com/rest/categorization'

def cmd_arguments():

    try:
        parser = argparse.ArgumentParser("This script checks domain reputation using Bluecoat reputation service.")

        parser.add_argument('--domain', required=True, help='Please specify domain name!',dest='domain')
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
        if cmd_args.domain:
            proxy_dict = {
                      'http':'http://{}:{}@{}:{}'.format(cmd_args.proxy_user,cmd_args.proxy_password,cmd_args.proxy_host,cmd_args.proxy_port),
                      'https':'http://{}:{}@{}:{}'.format(cmd_args.proxy_user,cmd_args.proxy_password,cmd_args.proxy_host,cmd_args.proxy_port),
                     }  
            logger.info("Proxies - {}".format(proxy_dict)) 
            post_data = {"url":"{}".format(cmd_args.domain)}
            response = requests.post(url,proxies=proxy_dict,data=post_data,verify=False)
            res_json=json.loads(response.text)
            if 'errorType' in res_json:
                site_category = res_json['errorType']
            else:
                soup_response = BeautifulSoup(res_json['categorization'], 'lxml')
                site_category = soup_response.find("a").text
        
            # Display warning if Bluecoat CAPTCHAs are activated
            if site_category == 'captcha':
                logger.warning('Blue Coat CAPTCHA is received. Kindly change your IP or manually solve a CAPTCHA at "https://sitereview.bluecoat.com/sitereview.jsp"')

            logger.info("Bluecoat reputation for site {} - {}".format(cmd_args.domain,site_category))

    except Exception as exc:
        logger.error("Error while getting site reputation information - %s" %exc.message,exc_info=True)

