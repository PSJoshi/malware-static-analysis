#!/usr/bin/env python
import sys
import hashlib
import logging
import requests
import argparse
import json
import yaml
import os
from bs4 import BeautifulSoup
import pycurl
import StringIO

# setup logging
logging.basicConfig(stream=sys.stdout,level = logging.DEBUG)
logger = logging.getLogger(__name__)

class hash_services():

    def __init__(self, config_file=None, check_file=None, hash_md5=None):

        self.config_file = config_file
        self.check_file = check_file
        self.hash_md5 = hash_md5
        self.hash_sha256 = None
        self.shadowserver_url = None
        self.shadowserver_whitelist_url = None
        self.threatexpert_url = None
        self.virustotal_url = None
        self.virustotal_api_key = None
        self.proxy_dict = dict()
        self.use_proxy = False
        self.proxy_auth_type = 'basic'
        self.proxy_host = ''
        self.proxy_port = 8080
        self.proxy_user = ''
        self.proxy_password = ''

        # check if config file path is OK
        if not (self.config_file and os.path.isfile(self.config_file)): 
            logger.error("The configuration file {} to be used for checking"
            " file reputation is not found.Quitting...".format(self.config_file))
            sys.exit(1)

        # check if file path is valid for file under test
        if not(self.check_file and os.path.isfile(self.check_file)): 
            logger.info("The file {} could not be found and hence, its reputation"
            " can not be determined".format(self.check_file))
             #sys.exit(1)

        # process configuration file 
        self._process_config()

    def _process_config(self):
        # process configuration file to find md5, sha256 hashes of check_file.
        # also build proxy_dict, shadowserver urls, threatexpert urls etc.
        try:
            config_data = self._yaml_config()
            if config_data: 
                # enable proxy or not. If yes, add proxy details
                if config_data['proxy']['enable']:
                    self.proxy_dict = {
                        'http':'http://{}:{}@{}:{}'.format(config_data['proxy']['user'],config_data['proxy']['password'],
                        config_data['proxy']['host'], config_data['proxy']['port']),
                    
                        'https':'http://{}:{}@{}:{}'.format(config_data['proxy']['user'],config_data['proxy']['password'],
                        config_data['proxy']['host'], config_data['proxy']['port'])
                        } 
                    self.proxy_user = config_data['proxy']['user']
                    self.proxy_password = config_data['proxy']['password']
                    self.proxy_host = config_data['proxy']['host']
                    self.proxy_port = config_data['proxy']['port']    
                    self.use_proxy = True
                    # proxy authentication - basic/digest
                    proxy_auth_type = config_data['proxy']['proxy_auth_type']
                    if proxy_auth_type.lower() == 'basic':             
                        self.proxy_auth_type = pycurl.HTTPAUTH_BASIC
                    else: 
                        self.proxy_auth_type = pycurl.HTTPAUTH_DIGEST
                else:
                    self.proxy_dict = dict()
                    self.use_proxy = False

            # compute md5 and sha256 checksum
            if not self.hash_md5: # md5 hash is not specified
                self.hash_md5 = self._md5_hash(self.check_file)
                self.hash_sha256 = self._sha256_hash(self.check_file)
            # prepare urls for various site feeds

            # shadowserver url
            if config_data['online-hash-services']['shadowserver']['enable']:
                logger.debug("Shadow server url - %s" % config_data['online-hash-services']['shadowserver']['url'])
                self.shadowserver_url = config_data['online-hash-services']['shadowserver']['url']
            else:
                self.shadowserver_url = None
            logger.info("Shadowserver url: {}".format( self.shadowserver_url))
            
            # shadowserver whitelist url  
            if config_data['online-hash-services']['shadowserver-whitelist']['enable']:
                logger.debug("Shadow server whitelist url - {}".format(config_data['online-hash-services']['shadowserver-whitelist']['url']))
                self.shadowserver_whitelist_url = config_data['online-hash-services']['shadowserver-whitelist']['url']
            else:
                self.shadowserver_whitelist_url = None
            logger.info("Shadowserver whitelist url: {}".format( self.shadowserver_whitelist_url))

            # check hash using threatexpert service
            if config_data['online-hash-services']['threatexpert']['enable']:
                logger.debug("Threat expert url - %s" % config_data['online-hash-services']['threatexpert']['url'])
                self.threatexpert_url = config_data['online-hash-services']['threatexpert']['url']

            # check hash using virustotal service
            if config_data['online-hash-services']['virustotal']['enable']:
                logger.debug("Virustotal url - %s" % config_data['online-hash-services']['virustotal']['url'])
                logger.debug("Virustotal key - %s" % config_data['online-hash-services']['virustotal']['key'])
                self.virustotal_url = config_data['online-hash-services']['virustotal']['url']
                self.virustotal_api_key = config_data['online-hash-services']['virustotal']['key']
            logger.info("Virustotal url: {} ".format(self.virustotal_url))


        except Exception,e:
            logger.error("Error while processing configuration of file {} - {}"
            .format(self.config_file,e.message),exc_info=True)
 

    def _yaml_config(self):

        configuration_data = None 
        try:
            # yaml configuration
            if os.path.isfile(self.config_file): 
                with open(self.config_file, 'r') as f:
                    configuration_data = yaml.load(f)
        except Exception,e:
            logger.error("Error while reading yaml configuration file {} - {}"
            .format(self.config_file,e.message), exc_info=True)    

        return configuration_data

    def _md5_hash(self, filename):
        md5 = None
        try:
            f = open(filename, "rb")
            data = f.read()
            md5 =  hashlib.md5(data).hexdigest()
            f.close()
        except Exception, e:
            logger.error("Error while computing md5 checksum for file {} - {}"
            .format(filename,e.message),exc_info=True)
        return md5

    def _sha256_hash(self, filename):
        sha256 = None
        try:
            f = open(filename, "rb")
            data = f.read()
            sha256 =  hashlib.sha256(data).hexdigest()
            f.close()
        except Exception, e:
            logger.error("Error while computing sha256 checksum for file {} - {}"
            .format(filename,e.message),exc_info=True)

        return sha256

    def _curl_response(self,url):

        try:
            response = None
            output = StringIO.StringIO()
            curl_instance = pycurl.Curl()
            curl_instance.setopt(pycurl.FOLLOWLOCATION,1)
            curl_instance.setopt(pycurl.USERAGENT, 'Mozilla/57.0 (Windows NT 6.3; Win64; x64)'
              ' AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2049.0 Safari/537.36')

            if self.use_proxy:
                curl_instance.setopt(pycurl.PROXY, self.proxy_host)
                curl_instance.setopt(pycurl.PROXYPORT, self.proxy_port)
                curl_instance.setopt(pycurl.PROXYAUTH, self.proxy_auth_type)
                curl_instance.setopt(pycurl.PROXYUSERPWD, "{}:{}".format(self.proxy_user, self.proxy_password))
            curl_instance.setopt(pycurl.VERBOSE, 0)
            curl_instance.setopt(pycurl.SSL_VERIFYPEER, 0)
            curl_instance.setopt(curl_instance.URL, url)
            curl_instance.setopt(curl_instance.WRITEDATA, output)
            curl_instance.perform()
            response = output.getvalue()
            curl_instance.close()

        except Exception,e:
            logger.error("Error while getting response from url {} - {}".format(url, e.message), exc_info=True) 

        return response
 
    def shadowserver_hash_report(self):
        try:
            response = None
            shadow_response = None 

            if not self.hash_md5:
                logger.info("MD5 hash of file {} is not valid. Quitting...")
                sys.exit(1)

            shadowserver_url = self.shadowserver_url + self.hash_md5
            response = self._curl_response(shadowserver_url)
 
            if response:
                logger.debug("Shadow server response - {}".format(response))
                split_response=response.strip().split(' ')[1:]
                hash_details = ''.join(split_response)
                logger.debug("Shadow server response - hash details - {}".format(hash_details))
                if hash_details:
                    shadow_response = json.loads(hash_details)
                return shadow_response

        except Exception,e:
            logger.error("Error while getting file hash information from Shadow Server - %s" %e.message,exc_info=True)    

        return shadow_response


    def shadowserver_whitelist_report(self):

        try:
            if not self.hash_md5:
                logger.info("MD5 hash of file {} is not valid. Quitting...")
                sys.exit(1)
            response = None
            shadowserver_whitelist_url = self.shadowserver_whitelist_url + self.hash_md5
            response = self._curl_response(shadowserver_whitelist_url)
            if response:
                # check if the hash is marked as whitelist or not
		whitelist_response=response.strip().split(',')[0]
                if "whitelisted" in whitelist_response.lower():
                    return True, whitelist_response
                else:  
                    return False, whitelist_response

            else: return False, ''  

        except Exception as e:
            logger.error("Error while getting file whitelist information from Shadow Server - %s" %e.message,exc_info=True)    
            # not whitelisted
            return False, ''

    def threatexpert_hash_report(self):

        try:
            if not self.hash_md5:
                logger.info("MD5 hash of file {} is not valid. Quitting...")
                sys.exit(1)

            response = None
            threatexpert_url = self.threatexpert_url + self.hash_md5
            response = self._curl_response(threatexpert_url)
            if response:
                soup = BeautifulSoup(response,'lxml')
                element_p = soup.findAll('p')     
                for item in element_p:
                    logger.info(item.text)
                    if 'no threatexpert reports found'.lower() in item.text.lower():
                        return False 
                return True  
        except Exception as e:
            logger.error("Error while getting file hash information from Threat expert - %s" %e.message,exc_info=True)    

        return False

    def virustotal_hash_report(self):

        try:
            if not self.hash_md5:
                logger.info("MD5 hash of file {} is not valid. Quitting...")
                sys.exit(1)

            vt_response = None
            virustotal_url = "{}?apikey={}&resource={}".format(self.virustotal_url,self.virustotal_api_key,self.hash_md5)
            response = self._curl_response(virustotal_url)
            if response:
                vt_response = json.loads(response)

        except Exception as e:
            logger.error("Error while getting file hash information from VirusTotal - %s" %e.message,exc_info=True)    

        return vt_response
