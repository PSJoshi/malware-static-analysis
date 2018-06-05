#!/usr/bin/env python

"""
 This script processes xml output of pestudio program - a very useful utility that analyzes EXE files for malicious
 contents.

 To get XML output:
 c:\pestudio> pestudioprompt.exe -file:c:\Users\Joshi\Desktop\putty.exe -xml:test.xml

"""

from xml.etree import ElementTree as ET
import re
import argparse
from urlparse import urlparse
import logging
import os
import sys

# setup logging
logging.basicConfig(stream=sys.stdout,level = logging.DEBUG)
logger = logging.getLogger(__name__)

def getXML_file(input_file):
    root = None
    try:
        root = ET.parse(input_file).getroot()
    except Exception as exc:
        logger.error("Error while parsing XML file {} - {}"
        .format(input_file,exc.message),exc_info=True)
    return root

def cmd_arguments():
    args = None
    try:
        parser = argparse.ArgumentParser("This script is used to parse XML reports of PEStudio for malware analysis.")

        parser.add_argument('--xml', required=True, help='Please specify PEStudio XML file.',dest='xml_file')
        args = parser.parse_args()

    except Exception as exc:
        logger.error("Error while getting command line arguments - %s" %exc.message,exc_info=True)
    return args

if __name__ == "__main__":
    try:
        cmd_args = cmd_arguments()

        dirname, filename = os.path.split(os.path.abspath(__file__))
        logger.debug("Directory - {} File- {}".format(dirname,filename))
        if not os.path.isfile(cmd_args.xml_file):
            logger.info("The file {} is could not be found. Quitting..".format(cmd_args.pestudio_xml))
            sys.exit(1) 

        xml_root = getXML_file(cmd_args.xml_file)
        pestudio_report = list()

        # parse indicators
        pestudio_indicators = xml_root.findall('Indicators')
        pestudio_dict = dict()
        for item in pestudio_indicators:
            logger.info("Number of indicators:{}".format(item.attrib))

        for indicators in pestudio_indicators:
            indicator_list = indicators.findall('Indicator')
            ind_list = list()
            for item in indicator_list:
               ind_list.append(item.text)
            pestudio_dict['indicators'] = ind_list

        pestudio_report.append(pestudio_dict)

        # parse strings
        pestudio_strings = xml_root.findall('strings')
        for item in pestudio_strings:
            logger.info("Number of strings:{}".format(item.attrib))

        pestudio_dict = dict()
        for strings in pestudio_strings:
            string_list = strings.findall('string')
            list_string = list()

            for item in string_list:
                # check for presence of ip address or url
                present_flag = False
                if item.text:
                    #ipv4 validation
                    if re.match('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', item.text) != None:
                        present_flag = True

                    # url validation
                    # if (re.findall('^http[s]?://\S+',item.text)):
                    #      present_flag = True

                    # url validation
                    url_result = urlparse(item.text)
                    if url_result.scheme in ('http','https'):
                        present_flag = True

                    if present_flag:
                        list_string.append(item.text)
                #list_string.append(item.text)
            if list_string:
                pestudio_dict['strings'] = list_string

        if pestudio_dict:
            pestudio_report.append(pestudio_dict)

        logger.info("{}".format(pestudio_report))

    except Exception as exc:
        logger.error("Error while running PEstudio parser script - {}".format(exc.message),exc_info=True)
