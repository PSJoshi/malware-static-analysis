#!/usr/bin/env python
import os
import yara
import logging
import yaml
import sys

# setup logging
logging.basicConfig(stream=sys.stdout,level = logging.DEBUG)
logger = logging.getLogger(__name__)

class yara_checks():

    def __init__(self,yara_rules_dir,yara_compiled_rules_dir):

        if not os.path.exists(yara_rules_dir):
            logger.error("Yara rules directory does not exists. Quitting...")
        # create compiled rules directory if required.
        if not os.path.exists(yara_compiled_rules_dir):
            logger.error("Yara rules directory containing compiled rules does not exist. Quitting...")

        self.yara_rules_dir = yara_rules_dir
        self.yara_compiled_rules_dir = yara_compiled_rules_dir

    def is_packed(self,filename):

        "check if the file is packed using packer tools like UPX etc"  
        rule_match = None
 
        if self.yara_rules_dir:
            packed_dir = os.path.join(os.path.sep,self.yara_rules_dir,'Packers')     

        if self.yara_compiled_rules_dir:
            compiled_packed_dir = os.path.join(os.path.sep,self.yara_compiled_rules_dir,'Packers')
            if not os.path.exists(compiled_packed_dir):
                os.mkdir(compiled_packed_dir) 

        for each_file in os.listdir(packed_dir):
            full_path = os.path.join(os.path.sep,packed_dir,each_file) 
            rule = yara.compile(full_path)
            full_path_compiled = os.path.join(os.path.sep,compiled_packed_dir,each_file)
            rule.save(full_path_compiled)
            rule = yara.load(full_path_compiled)
            rule_match = rule.match(filename)   
            if rule_match:
                return rule_match

        return rule_match


    def is_malicious_document(self,filename):

        "check if the file is malicious MS-WORD file"  
        rule_match = None

        if self.yara_rules_dir:
            packed_dir = os.path.join(os.path.sep,self.yara_rules_dir,'Malicious_Documents')     

        if self.yara_compiled_rules_dir:
            compiled_packed_dir = os.path.join(os.path.sep,self.yara_compiled_rules_dir,'Malicious_Documents')
            if not os.path.exists(compiled_packed_dir):
                os.mkdir(compiled_packed_dir) 

        for each_file in os.listdir(packed_dir):
            full_path = os.path.join(os.path.sep,packed_dir,each_file) 
            rule = yara.compile(full_path)
            full_path_compiled = os.path.join(os.path.sep,compiled_packed_dir,each_file)
            rule.save(full_path_compiled)
            rule = yara.load(full_path_compiled)
            rule_match = rule.match(filename)   
            if rule_match:
                return rule_match

        return rule_match 

    def is_antiVM(self,filename):

        " check if file contains anti Debug or anti virtual machine detection features" 
        rule_match = None

        if self.yara_rules_dir:
            packed_dir = os.path.join(os.path.sep,self.yara_rules_dir,'Antidebug_AntiVM')     

        if self.yara_compiled_rules_dir:
            compiled_packed_dir = os.path.join(os.path.sep,self.yara_compiled_rules_dir,'Antidebug_AntiVM')
            if not os.path.exists(compiled_packed_dir):
                os.mkdir(compiled_packed_dir) 

        for each_file in os.listdir(packed_dir):
            full_path = os.path.join(os.path.sep,packed_dir,each_file) 
            rule = yara.compile(full_path)
            full_path_compiled = os.path.join(os.path.sep,compiled_packed_dir,each_file)
            rule.save(full_path_compiled)
            rule = yara.load(full_path_compiled)
            rule_match = rule.match(filename)   
            if rule_match:
                return rule_match
        
        return rule_match

    def is_cryptofeatures(self,filename):

        " check if file has crypto related features - like encryption functions, CRC16 function, CRC32 function, hash functions etc  " 
        rule_match = None

        if self.yara_rules_dir:
            packed_dir = os.path.join(os.path.sep,self.yara_rules_dir,'Crypto')     

        if self.yara_compiled_rules_dir:
            compiled_packed_dir = os.path.join(os.path.sep,self.yara_compiled_rules_dir,'Crypto')
            if not os.path.exists(compiled_packed_dir):
                os.mkdir(compiled_packed_dir) 

        for each_file in os.listdir(packed_dir):
            full_path = os.path.join(os.path.sep,packed_dir,each_file) 
            rule = yara.compile(full_path)
            full_path_compiled = os.path.join(os.path.sep,compiled_packed_dir,each_file)
            rule.save(full_path_compiled)
            rule = yara.load(full_path_compiled)
            rule_match = rule.match(filename)   
            if rule_match: 
                return rule_match

        return rule_match 


    def is_malware(self,filename):

        " check if file matchs any malware signature(s)  " 
        rule_match = None

        if self.yara_rules_dir:
            packed_dir = os.path.join(os.path.sep,self.yara_rules_dir,'malware')     

        if self.yara_compiled_rules_dir:
            compiled_packed_dir = os.path.join(os.path.sep,self.yara_compiled_rules_dir,'malware')
            if not os.path.exists(compiled_packed_dir):
                os.mkdir(compiled_packed_dir) 

        for each_file in os.listdir(packed_dir):
            full_path = os.path.join(os.path.sep,packed_dir,each_file) 
            rule = yara.compile(full_path)
            full_path_compiled = os.path.join(os.path.sep,compiled_packed_dir,each_file)
            rule.save(full_path_compiled)
            rule = yara.load(full_path_compiled)
            rule_match = rule.match(filename)   
            if rule_match: 
                return rule_match

        return rule_match 


    def is_exploitkit(self,filename):

        " check if file matchs any exploitkit signature(s)  " 
        rule_match = None

        if self.yara_rules_dir:
            packed_dir = os.path.join(os.path.sep,self.yara_rules_dir,'Exploit-Kits')     

        if self.yara_compiled_rules_dir:
            compiled_packed_dir = os.path.join(os.path.sep,self.yara_compiled_rules_dir,'Exploit-Kits')
            if not os.path.exists(compiled_packed_dir):
                os.mkdir(compiled_packed_dir) 

        for each_file in os.listdir(packed_dir):
            full_path = os.path.join(os.path.sep,packed_dir,each_file) 
            rule = yara.compile(full_path)
            full_path_compiled = os.path.join(os.path.sep,compiled_packed_dir,each_file)
            rule.save(full_path_compiled)
            rule = yara.load(full_path_compiled)
            rule_match = rule.match(filename)   
            if rule_match: 
                return rule_match

        return rule_match 

    def is_webshell(self,filename):

        " check if file contains any webshells" 
        rule_match = None

        if self.yara_rules_dir:
            packed_dir = os.path.join(os.path.sep,self.yara_rules_dir,'Webshells')     

        if self.yara_compiled_rules_dir:
            compiled_packed_dir = os.path.join(os.path.sep,self.yara_compiled_rules_dir,'Webshells')
            if not os.path.exists(compiled_packed_dir):
                os.mkdir(compiled_packed_dir) 

        for each_file in os.listdir(packed_dir):
            full_path = os.path.join(os.path.sep,packed_dir,each_file) 
            rule = yara.compile(full_path)
            full_path_compiled = os.path.join(os.path.sep,compiled_packed_dir,each_file)
            rule.save(full_path_compiled)
            rule = yara.load(full_path_compiled)
            rule_match = rule.match(filename)   
            if rule_match: 
                return rule_match

        return rule_match 


    def is_CVErules(self,filename):

        " check if file matches any of the exploitable CVE vulnerability payloads" 
        rule_match = None

        if self.yara_rules_dir:
            packed_dir = os.path.join(os.path.sep,self.yara_rules_dir,'CVE_Rules')     

        if self.yara_compiled_rules_dir:
            compiled_packed_dir = os.path.join(os.path.sep,self.yara_compiled_rules_dir,'CVE_Rules')
            if not os.path.exists(compiled_packed_dir):
                os.mkdir(compiled_packed_dir) 

        for each_file in os.listdir(packed_dir):
            full_path = os.path.join(os.path.sep,packed_dir,each_file) 
            rule = yara.compile(full_path)
            full_path_compiled = os.path.join(os.path.sep,compiled_packed_dir,each_file)
            rule.save(full_path_compiled)
            rule = yara.load(full_path_compiled)
            rule_match = rule.match(filename)   
            if rule_match: 
                return rule_match

        return rule_match
