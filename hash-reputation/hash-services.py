#!/usr/bin/env python
import sys
import logging
import requests
import argparse
import json
import yaml
import os
from bs4 import BeautifulSoup
from pprint import pprint 

"""
This script uses file repuation services on the web to check if the file is malicious or not.
File reputation services:

Virustotal service(public key api - 4 requests per min constraint):

Threatexpert: http://threatexpert.com/reports.aspx
e.g.
http://threatexpert.com/reports.aspx?find=7e010e90d1dbd292de3d2ae20e04b7ba

Shadowserver: http://bin-test.shadowserver.org
This server allows us to test an executable against a list of known software applications using md5/sha1 hash.
e.g.
    Details of program associated with hash:
    http://bin-test.shadowserver.org/api?md5=0E53C14A3E48D94FF596A2824307B492
    http://bin-test.shadowserver.org/api?sha1=000000206738748EDD92C4E3D2E823896700F849 

    Check if program is whitelisted or not:
    http://innocuous.shadowserver.org/api/?query=0E53C14A3E48D94FF596A2824307B492
Team cymru report

"""
# setup logging
logging.basicConfig(stream=sys.stdout,level = logging.DEBUG)
logger = logging.getLogger(__name__)

def yaml_config(yaml_file):
    try:
        with open(yaml_file, 'r') as f:
            configuration_data = yaml.load(f)
        return configuration_data

    except Exception as exc:
        logger.error("Error while reading yaml configuration file - %s" %e.message,exc_info=True)    

def md5sum(file):
    try:
        f = open(file, "rb")
        data = f.read()
        md5 =  hashlib.md5(data).hexdigest()
        f.close()
    except Exception, msg:
        print msg

    return md5

def sha256sum(file):
    try:
        f = open(file, "rb")
        data = f.read()
        sha256 =  hashlib.sha256(data).hexdigest()
        f.close()
    except Exception, msg:
        print msg

    return sha256


def shadowserver_hash_report(url,file_hash,proxy_dict = None):
    try:
        response = None
        shadow_response = None 
        headers = {'Accept-Encoding': "gzip, deflate", 'User-Agent': 'Python-based agent'}
        url = url + file_hash
        response = requests.get(url,proxies=proxy_dict,headers = headers)
        if response.status_code == 200:
            if (response.text):
                r = response.text
		split_response=r.strip().split(' ')[1:]
                hash_details = ''.join(split_response)
                if hash_details:
                    shadow_response = json.loads(hash_details)
                    return shadow_response
        return shadow_response
    except Exception as e:
        logger.error("Error while getting file hash information from Shadow Server - %s" %e.message,exc_info=True)    

def shadowserver_whitelist_report(url,file_hash,proxy_dict=None):
    try:
        response = None
        headers = {'Accept-Encoding': "gzip, deflate", 'User-Agent': 'Python-based agent'}
        url = url + file_hash
        response = requests.get(url,proxies=proxy_dict,headers = headers)
        if response.status_code == 200:
            if (response.text):
                r = response.text
                # check if the hash is marked as whitelist or not
		whitelist_response=r.strip().split(',')[0]
                if "whitelisted" in whitelist_response.lower():
                    return True, whitelist_response  
        # not whitelisted
        return False, ''

    except Exception as e:
        logger.error("Error while getting file whitelist information from Shadow Server - %s" %e.message,exc_info=True)    


def threatexpert_report(url, file_hash,proxy_dict=None):
    try:
        response = None
        headers = {'Accept-Encoding': "gzip, deflate", 'User-Agent': 'Python-based agent'}
        url = url + file_hash
        response = requests.get(url,proxies=proxy_dict,headers = headers)
        if response.status_code == 200:
            if response.text:
                soup = BeautifulSoup(response.text,'lxml')
                element_p = soup.findAll('p')     
                for item in element_p:
                    logger.info(item.text)
                    if 'no threatexpert reports found'.lower() in item.text.lower():
                        return False 
        return True  
    except Exception as e:
        logger.error("Error while getting file hash information from Threat expert - %s" %e.message,exc_info=True)    


def virustotal_report(url, api_key, file_hash,proxy_dict=None):
    try:
        vt_response = None
        params = {'apikey': api_key, 'resource': file_hash}
        headers = {'Accept-Encoding': "gzip, deflate", 'User-Agent': 'Python-based VirtualTotal agent'}
        response = requests.get(url, proxies=proxy_dict, params=params, headers=headers)
        if response.status_code == 200:
            if response.text:
                vt_response = json.dumps(response.text) 
        return vt_response

    except Exception as e:
        logger.error("Error while getting file hash information from VirusTotal - %s" %e.message,exc_info=True)    

    return vt_response

def cmd_arguments():

    try:
        parser = argparse.ArgumentParser("This script uses file repuation services on the internet to check if the file is malicious or not.")
        parser.add_argument('--config', required=True, help='Please specify configuration file',dest='config_file')
        parser.add_argument('--md5-hash', required=True, help='Please specify md5 hash',dest='hash')
        args = parser.parse_args()
        return args
    except Exception as exc:
        logger.error("Error while getting command line arguments - %s" %exc.message,exc_info=True)

if __name__ == "__main__":
    try:

        cmd_args = cmd_arguments()
        if cmd_args:

            # read yaml configuration
            if os.path.isfile(cmd_args.config_file):
                config = yaml_config(cmd_args.config_file)
                #logger.info(pprint(config))

                # enable proxy or not. If yes, add proxy details
                if config['proxy']['enable']:
                    proxy_dict = {
                      'http':'http://{}:{}@{}:{}'.format(config['proxy']['user'],config['proxy']['password'],
                           config['proxy']['host'], config['proxy']['port']),
                      'https':'http://{}:{}@{}:{}'.format(config['proxy']['user'],config['proxy']['password'],
                           config['proxy']['host'], config['proxy']['port'])
                    } 
                else:
                    proxy_dict = {}

                # check hash using threatexpert service
                if config['online-hash-services']['threatexpert']['enable']:
                    logger.debug("Threat expert url - %s" % config['online-hash-services']['threatexpert']['url'])
                    url = config['online-hash-services']['threatexpert']['url']
                    threatexpert_response = threatexpert_report(url,cmd_args.hash,proxy_dict)
                    logger.info(threatexpert_response)


                # check hash using shadowserver whitelist service
                if config['online-hash-services']['shadowserver-whitelist']['enable']:
                    logger.debug("Shadow server whitelist url - %s" % config['online-hash-services']['shadowserver-whitelist']['url'])
                    url = config['online-hash-services']['shadowserver-whitelist']['url']
                    iswhitelisted, response = shadowserver_whitelist_report(url,cmd_args.hash,proxy_dict)
                    logger.debug("Shadow server whitelist service response - {}".format(response))      
                    if iswhitelisted:
                        logger.info("Shadow server whitelist service reponse says that The hash {} is whitelisted".format(cmd_args.hash))
                    else:
                        logger.info("Shadow server whitelist service reponse says that The hash {} is not whitelisted".format(cmd_args.hash))

                # check hash using shadowserver hash service
                if config['online-hash-services']['shadowserver']['enable']:
                    logger.debug("Shadow server url - %s" % config['online-hash-services']['shadowserver']['url'])
                    url = config['online-hash-services']['shadowserver']['url']
                    shadowserver_response = shadowserver_hash_report(url,cmd_args.hash,proxy_dict)
                    logger.info(shadowserver_response)
 
                # check hash using virustotal service
                if config['online-hash-services']['virustotal']['enable']:
                    logger.debug("Virustotal url - %s" % config['online-hash-services']['virustotal']['url'])
                    logger.debug("Virustotal key - %s" % config['online-hash-services']['virustotal']['key'])
                    url = config['online-hash-services']['virustotal']['url']
                    api_key = config['online-hash-services']['virustotal']['key']
                    virustotal_response = virustotal_report(url,api_key,cmd_args.hash,proxy_dict)
                    logger.info(virustotal_response)


            else:
                logger.info("YAML configuration file %s is not found." %cmd_args.config)
          
    except Exception as e:
        logger.error("Error while getting file hash information - %s" %e.message,exc_info=True)

