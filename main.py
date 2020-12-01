###########################################################
############## Created by Devin Marks #####################
############# Spikefish Solutions Inc. ####################
###########################################################

###########################################################
# With a group of Check Point MDSs in Zabbix, this script #
### will query all of those MDSs for all objects under ####
###### each MDS and automatically add them to Zabbix ######
###########################################################

import sys
import getopt
from zabbix.api import ZabbixAPI
from cpapi import APIClient
from spikefish.spikefish_libs.logging import logging
from module import Pointix
from spikefish.checkpoint.apiv161.cp_apicalls import cpAuth


def main(argv):
    try:
        opts, args = getopt.getopt(argv, 'c:d:z:s:')
    except getopt.GetoptError:
        print('usage: main.py -c <MDSIP> -d <domain> -z <ZABBIXURL> -s <SNMPVERSION(2 or 3)>')
        return
    arguements = dict(opts)

    # Initiate the Pointix object
    pointix = Pointix(arguements['-c'], arguements['-d'], arguements['-z'], arguements['-s'])

    # Read the groups from the groups-templates file
    pointix.getGroups()

    # Read the required files into lists and dictionaries
    pointix.getCreds()
    pointix.getFiles()

    # Authenticate to the Check Point Global and Zabbix APIs
    pointix.authCheckPointGlobal()
    pointix.authZabbix()
    
    # Convert the Zabbix group and templates names to IDs
    pointix.getAllGroups()

    # Obtain the management servers, gateways, and clusters from the Check Point API specified domain
    pointix.getManageServers()
    pointix.authCheckPointDomain()
    pointix.getGateways()
    pointix.getClusters()

    # Add the devices to Zabbix
    pointix.addAllManagement()
    pointix.addAllGateways()
    pointix.addAllClusters()

    # Print the results of the devices adding to Zabbix
    pointix.printResults()
    pointix.logResults()


if __name__ == '__main__':
    main(sys.argv[1:])