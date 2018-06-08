#!/usr/bin/env python
import sys
import logging
import requests
import argparse
import yaml
import os
from pprint import pprint
from hash_services import hash_services
from virustotal_services import Virustotal
from shodan_services import Shodan_checks

from time import sleep

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


def cmd_arguments():

    try:
        parser = argparse.ArgumentParser("This script uses file repuation services on the internet to check if the file is malicious or not.")
        parser.add_argument('--config', required=True, help='Please specify configuration file',dest='config_file')
        parser.add_argument('--hash-file', required=False, help='Please specify the file to be checked for its reputation',dest='hash_file')
        parser.add_argument('--md5-hash', required=False, help='Please specify md5 hash',dest='hash')
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
                config_data = yaml_config(cmd_args.config_file)
                logger.debug(pprint(config_data))


            # Shodan information
            logger.info("Getting information using Shodan servers APIs...")
            shodan_instance = Shodan_checks(config_data['shodan-services']['key'],
                              config_data['shodan-services']['url'],
                              config_data['proxy']['enable'], config_data['proxy']['proxy_auth_type'],
                              config_data['proxy']['host'], config_data['proxy']['port'],
                              config_data['proxy']['user'], config_data['proxy']['password'])

            # get API information
            logger.info("Getting Shodan API status information.")
            shodan_instance.api_information()
            logger.info("Shodan API status information is fetched successfully.")
            
            ### HTTP client headers information
            logger.info("Getting HTTP client headers using Shodan API.")
            shodan_instance.http_headers()
            logger.info("HTTP client headers are fetched successfully.")

            ### IP information 
            logger.info("Getting IP information using Shodan API.")
            shodan_instance.ip_information('59.185.236.31')
            logger.info("IP information is fetched successfully.")

            ### Scanning ports usage
            logger.info("Checking scan ports using Shodan API.")
            shodan_instance.scanning_ports()
            logger.info("Scan Ports information is fetched successfully.")

            #### check if VPN ports are open
            logger.info("Checking if VPN ports are open or not using Shodan API")
            shodan_instance.is_vpn('59.185.236.31')   
            logger.info("VPN ports information is fetched successfully.")
  
            hash_val = '7657fcb7d772448a6d8504e4b20168b8'
           # Use of different hash services available on web to find out malicious files
            hash_service_instance = hash_services(cmd_args.config_file,cmd_args.hash_file)

            #shadow server hash report
            logger.info("Getting Shadow server hash report...")
            response = hash_service_instance.shadowserver_hash_report()
            logger.info("Shadow server hash report:\n {}".format(response))

            # shadow server whitelist response
            logger.info("Getting Shadow server whitelist report...")
            whitelist_status, whitelist_response = hash_service_instance.shadowserver_whitelist_report()
            logger.info("Shadow server whitelist report:\n {}- {}".format(whitelist_status, whitelist_response))

            #threat expert report
            logger.info("Getting Threatexpert report...") 
            response = hash_service_instance.threatexpert_hash_report()
            logger.info("Threatexpert hash report:\n {}".format(response))

            #virustotal report
            logger.info("Getting virustotal report...")
            response = hash_service_instance.virustotal_hash_report()
            logger.info("Virustotal hash report:\n {}".format(response))

            logger.info("Getting Virustotal response for hash {}".format(hash_val))

            # use virustotal service to find malicious hash,url,ip information
            vt = Virustotal(config_data['online-hash-services']['virustotal']['key'],
            config_data['proxy']['enable'], config_data['proxy']['proxy_auth_type'],
            config_data['proxy']['host'], config_data['proxy']['port'],
            config_data['proxy']['user'], config_data['proxy']['password'])

            # Virustotal file report
            logger.info("Getting Virustotal file report..")
            if os.path.isfile(cmd_args.hash_file):
                response = vt.file_report(cmd_args.hash_file)
                logger.info("Virustotal report of file {}:\n {}".format(cmd_args.hash_file,response))
                sleep(10)
            else:
                logger.info("The file {} is not present on the system."
                "Kindly re-check the path and then try again.".format(cmd_args.hash_file))

            # Virustotal hash report
            logger.info("Getting Virustotal hash report...")
            response = vt.hash_report(hash_val)
            logger.info("Virustotal report for hash {}:\n{}".format(hash_val,response))
            sleep(10)
            
            # Virustotal url report  
            logger.info("Getting Virustotal url report...")
            url = 'http://www.barc.gov.in'
            response = vt.url_report(url)
            logger.info("Virustotal report for url {}:\n{}".format(url,response))
            sleep(10)

            # Virustotal ip report  
            logger.info("Getting Virustotal ip report...")
            test_ip = '59.185.236.31'
            response = vt.ip_report(test_ip)
            logger.info("Virustotal report for ip {}:\n{}".format(test_ip,response))
            sleep(10)

            # Virustotal domain report
            logger.info("Getting Virustotal domain report...") 
            test_domain = '027.ru'
            response = vt.domain_report(test_domain)
            logger.info("Virustotal report for domain {}:\n".format(test_domain,response))
            sleep(10)
 
            
    except Exception,e:
        logger.error("Error while running the python script - {}".format(e.message),exc_info=True)
