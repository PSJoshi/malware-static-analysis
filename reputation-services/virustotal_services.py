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
import hashlib

# setup logging
logging.basicConfig(stream=sys.stdout,level = logging.ERROR)
logger = logging.getLogger(__name__)

class Virustotal():

    def __init__(self,api_key = None, use_proxy = False, proxy_auth_type = 'basic',
                 proxy_host = None, proxy_port=8080, proxy_user=None,
                 proxy_password = None):
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

    def valid_ip(self,ip_addr):
        try:
            ip_addr = unicode(ip_addr)
            res = ipaddress.ip_address(ip_addr)
            return True
        except Exception:
            return False

    def file_report(self,filename):

        vt_response = None
        try:
            vt_url = 'https://www.virustotal.com/vtapi/v2/file/report'
            if not os.path.isfile(filename):
                logger.error("The file path {} is not valid!".format(filename))
                return vt_reponse

            # compute file hash  
            file_hash = self._md5_hash(filename)
 
            if self.api_key:
                post_parameters = [('resource', file_hash),
                            ('apikey',self.api_key)]  
                vt_response = self._curl_response(vt_url, 'POST', post_parameters)
                if vt_response:
                    logger.debug("Virustotal API results for file hash {} - {}"
                    .format(file_hash,vt_response))

        except Exception,e:
            logger.error("Error while retriving virustotal file report for file {} - {}"
            .format(filename,e.message),exc_info = True) 

        return vt_response

    def hash_report(self,hash_val):

        vt_response = None
        try:
            vt_url = 'https://www.virustotal.com/vtapi/v2/file/report'
 
            if self.api_key:
                post_parameters = [('resource', hash_val),
                            ('apikey',self.api_key)]  
                vt_response = self._curl_response(vt_url, 'POST', post_parameters)
                if vt_response:
                    logger.debug("Virustotal API results for hash {} - {}"
                    .format(hash_val,vt_response))

        except Exception,e:
            logger.error("Error while retriving virustotal report for hash {} - {}"
            .format(hash_val,e.message),exc_info = True) 

        return vt_response

    def url_report(self,url):

        vt_response = None
        try:
            if not url.find('http')>=0:
                url = 'http://' + url
 
            vt_url = 'http://www.virustotal.com/vtapi/v2/url/report'
            if self.api_key:
                post_parameters = [('resource', url),
                            ('apikey',self.api_key)]  
                vt_response = self._curl_response(vt_url, 'POST', post_parameters)
                if vt_response:
                    logger.debug("Virustotal API results for url {} - {}"
                    .format(url,vt_response))

        except Exception,e:
            logger.error("Error while retriving virustotal url report for url {} - {}"
            .format(url,e.message),exc_info=True)

        return vt_response

    def ip_report(self,ip_addr):

        vt_response = None
        try:
            if not self.valid_ip(ip_addr):
                logger.error("IP address {} is not valid. Quitting..") 
                return vt_reponse
 
            vt_url = 'http://www.virustotal.com/vtapi/v2/ip-address/report'
            if self.api_key:
                parameters = {'ip': ip_addr,
                              'apikey': self.api_key
                             }    
                vt_response = self._curl_response(vt_url, 'GET', parameters)
                if vt_response:
                    logger.debug("Virustotal API results for ip address {} - {}"
                    .format(ip_addr,vt_response))

        except Exception,e:
            logger.error("Error while retriving virustotal ip address report for ip {} - {}"
            .format(ip_addr,e.message),exc_info=True)

        return vt_response 

    def domain_report(self,domain):

        vt_response = None
        try:
            if not validators.domain(domain):
                logger.error("Domain {} is not valid. Quitting..") 
                return vt_reponse
 
            vt_url = 'http://www.virustotal.com/vtapi/v2/domain/report'
            if self.api_key:
                parameters = {'domain': domain,
                                   'apikey': self.api_key 
                                  }
                vt_response = self._curl_response(vt_url, 'GET', parameters)
                if vt_response:
                    logger.debug("Virustotal API results for domain {} - {}"
                    .format(domain,vt_response))

        except Exception,e:
            logger.error("Error while retriving virustotal domain report for domain {} - {}"
            .format(domain,e.message),exc_info=True)

        return vt_response 


    def _curl_response(self, url = None, request_type='GET', parameters = None):

        try:
            response = None
            output = StringIO.StringIO()
            curl_instance = pycurl.Curl()
            if request_type == 'POST' and parameters: 
                curl_instance.setopt(curl_instance.HTTPPOST,parameters)
            elif request_type == 'GET' and parameters:  
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

