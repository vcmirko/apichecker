# -*- coding: utf-8 -*-
"""
Created on Fri Sep  10 9:03:11 2022

@author: mirko
"""

# snmp
from pysnmp.hlapi import *
import smtplib

# data formats
import json
import yaml

# argument parser
import argparse

# nice logging
import logging

# rest api
import requests

# jq filtering on json
import pyjq

# disable warnings https certs
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

### reset logging (to avoid double logging)
def reset_logging():
    """Reset Logging"""
    manager = logging.root.manager
    manager.disabled = logging.NOTSET
    airflow_loggers = [
        logger for logger_name, logger in manager.loggerDict.items() if logger_name.startswith('airflow')
    ]
    for logger in airflow_loggers:  # pylint: disable=too-many-nested-blocks
        if isinstance(logger, logging.Logger):
            logger.setLevel(logging.NOTSET)
            logger.propagate = True
            logger.disabled = False
            logger.filters.clear()
            handlers = logger.handlers.copy()
            for handler in handlers:
                # Copied from `logging.shutdown`.
                try:
                    handler.acquire()
                    handler.flush()
                    handler.close()
                except (OSError, ValueError):
                    pass
                finally:
                    handler.release()
                logger.removeHandler(handler) 

#=======================
# START CODE

# parse arguments
parser = argparse.ArgumentParser()
parser.add_argument("config", help="Path of the config yaml file")
args = parser.parse_args()
configpath = args.config

# open configfile
with open(args.config) as file:
     config=yaml.load(file, Loader=yaml.FullLoader)

# set logger
reset_logging()
logger = logging.getLogger("OntapChecker")

logger.setLevel(logging.INFO)
if config["logger"]["verbose"]:
    logger.setLevel(logging.DEBUG)
if not config["logger"]["enabled"]:
    logger.setLevel(logging.NOTSET)

fh = logging.FileHandler(config["logger"]["file"])
formatter = logging.Formatter(config["logger"]["format"])
fh.setFormatter(formatter)

ch = logging.StreamHandler()
ch.setFormatter(formatter)

logger.addHandler(fh)
logger.addHandler(ch)
logger.propagate = False
     
# start check

logger.info("---------------------------")
logger.info("STARTING checker")
     
# loop hosts

for host in config["hosts"]:
    logger.info("Checking host '{}'".format(host["name"]))
    
    # loop checks
    
    for check in config["checks"]:
        
        logger.info("Checking {}".format(check["name"]))
        jq = check["jq"]
        
        # loading isl from file (for debug)
        # with open(check["debugfile"]) as json_file:
        #     check_data = json.load(json_file)
		
        # do rest call
        url = "http{}://{}/{}".format(("s" if host["secure"] else ""),host["fqdn"],check["api"])
        logger.debug("Connecting rest api : {}".format(url))
        response = requests.get(url, auth=(host["username"],host["password"]), verify=False)
        check_data = response.json()
        
        logger.debug("raw json : {}".format(check_data))
            
        # get results
        results = pyjq.one(jq["results"],check_data)
        
        logger.debug("results : {}".format(check_data))        
        
        # process results
        for result in results:
            
            # get detailed info from result
            objname = pyjq.one(jq["name"],result)
            objvalue = pyjq.one(jq["value"],result)
            objmessage = "{} -> {}".format(objname,objvalue)
            subject = pyjq.one(jq["description"],result)
            systemname = host["name"]
            systemdescription = host["description"]
            
            logger.info("Checking : {}".format(objname))      

            # do the check             
            checkresult = check["value"]==objvalue
            
            # negate check if needed
            if check["negated"]:
                checkresult=not checkresult
                
            # if check is not ok
            if checkresult:
                
                logger.error(objmessage)

                # snmp trap                
                if config["snmp"]["enabled"]:
                    
                    logger.info("Sending snmp trap")
                    
                    iterator = sendNotification(
                        SnmpEngine(),
                        CommunityData(config["snmp"]["community"], mpModel=0),
                        UdpTransportTarget((config["snmp"]["target"], config["snmp"]["port"])),
                        ContextData(),
                        'trap',
                        NotificationType(
                            ObjectIdentity(check["snmp"]["oid"]["traptype"])
                        ).addVarBinds(
                            ('1.3.6.1.6.3.18.1.3.0', config["snmp"]["source"]),
                            (check["snmp"]["oid"]["name"], OctetString(systemname)),
                            (check["snmp"]["oid"]["description"], OctetString(systemdescription)),
                            (check["snmp"]["oid"]["object"], OctetString(objmessage))
                        ).loadMibs(
                            'SNMPv2-MIB', 'SNMP-COMMUNITY-MIB'
                        )
                    )
                            
                    errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
                    
                    if errorIndication:
                       logger.error(errorIndication)
                
                # email
                if config["smtp"]["enabled"]:
                    
                    logger.info("Sending email")
                    
                    sender = config["smtp"]["from"]
                    receiver = config["smtp"]["to"]
                    message = 'To: {}\nFrom: {}\nSubject: {}\n\nSystem: {}\nDescription: {}\nProblem: {}'.format(receiver,sender,subject,systemname,systemdescription,objmessage)
             
                    logger.debug(message)
                    
                    try:
                        if(config["smtp"]["ssl"]):
                            smtpObj = smtplib.SMTP_SSL(config["smtp"]["host"],config["smtp"]["port"])
                        else:
                            smtpObj = smtplib.SMTP(config["smtp"]["host"],config["smtp"]["port"])
                        smtpObj.sendmail(sender, receiver, message)         

                    except SMTPException:
                        logger.error(SMTPException)

                
            else:
                logger.debug("Check is OK")
        
