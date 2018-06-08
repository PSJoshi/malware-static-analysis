#!/usr/bin/env python
import pycurl
import StringIO
import os
import sys
import time
import ipaddress
import validators
import urllib
import logging
import json

# setup logging
logging.basicConfig(stream=sys.stdout,level = logging.ERROR)
logger = logging.getLogger(__name__)

class Shodan_checks():

    api_base_url = 'https://api.shodan.io'

    def __init__(self,api_key=None, base_url=None,use_proxy = False,
                 proxy_auth_type = 'basic', proxy_host = None, 
                 proxy_port=8080, proxy_user=None,proxy_password = None):

        self.api_key = api_key
        self.use_proxy = use_proxy
        self.proxy_host = proxy_host
        self.proxy_port = 8080
        self.proxy_user = proxy_user
        self.proxy_password = proxy_password
        if proxy_auth_type.lower() == 'basic':             
            self.proxy_auth_type = pycurl.HTTPAUTH_BASIC
        else: 
            self.proxy_auth_type = pycurl.HTTPAUTH_DIGEST
    
        # shodan base url
        self.base_url = base_url or api_base_url
    
    def valid_ip(self,ip_addr):
        try:
            ip_addr = unicode(ip_addr)
            res = ipaddress.ip_address(ip_addr)
            return True
        except Exception:
            return False    

    def _curl_response(self, url = None, request_type='GET', parameters = None):

        try:
            response = None
            output = StringIO.StringIO()
            curl_instance = pycurl.Curl()
            if request_type == 'POST':
                if parameters: 
                    curl_instance.setopt(curl_instance.HTTPPOST,parameters)
            elif request_type == 'GET':
                if parameters:  
                    url = url + '?' + urllib.urlencode(parameters)

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
            logger.error("Error while getting response from Virustotal API service - {}".format(e.message), exc_info=True) 

        return response

    def api_information(self):

        json_response = None
        try:
            shodan_url = self.base_url + '/api-info?key={}'.format(self.api_key)
            shodan_response= self._curl_response(shodan_url, 'GET', None)
            if shodan_response:
                logger.info("Shodan response:{}".format(shodan_response)) 
                json_response = json.loads(shodan_response)
        except Exception,exc:
            logger.error("Error while getting Shodan API status information - {}".format(exc.message),exc_info=True)
        return json_response


    def ip_information(self,ip=None):
    
        json_response = None
        try:
            shodan_url = self.base_url + '/shodan/host/{}?key={}'.format(ip,self.api_key)
            shodan_response= self._curl_response(shodan_url, 'GET', None)
            if shodan_response:
                logger.info("Shodan response:{}".format(shodan_response)) 
                json_response = json.loads(shodan_response)
        except Exception,exc:
            logger.error("Error while getting IP information from Shodan API - {}".format(exc.message),exc_info=True)

        return json_response

    def scanning_ports(self):

        json_response = None
        try:
            shodan_url = self.base_url + '/shodan/ports?key={}'.format(self.api_key)
            shodan_response= self._curl_response(shodan_url, 'GET', None)
            if shodan_response:
                logger.info("Shodan response:{}".format(shodan_response)) 
                json_response = json.loads(shodan_response)
        except Exception,exc:
            logger.error("Error while getting port information from Shodan API - %s" %exc.message,exc_info=True)

        return json_response

    def is_vpn(self,ip=None):
        json_response = None
        try:
            shodan_url = self.base_url + '/shodan/host/{}?key={}'.format(ip,self.api_key)
            shodan_response= self._curl_response(shodan_url, 'GET', None)
            if shodan_response:
                logger.info("Shodan response:{}".format(shodan_response)) 
                json_response = json.loads(shodan_response)
                for banner in json_response['data']:
                    if banner['port'] in [500, 4500]:
                       return True
        except Exception,exc:
            logger.error("Error while detecting VPN from Shodan API - %s" %exc.message,exc_info=True)
    
        return False


    def http_headers(self):

        json_response = None
        try:
            shodan_url = self.base_url + '/tools/httpheaders?key={}'.format(self.api_key)
            shodan_response= self._curl_response(shodan_url, 'GET', None)
            if shodan_response:
                logger.info("Shodan response:{}".format(shodan_response)) 
                json_response = json.loads(shodan_response)

        except Exception,exc:
            logger.error("Error while getting client HTTP headers information from Shodan API - %s" %exc.message,exc_info=True)

        return json_response
  
