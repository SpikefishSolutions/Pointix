###########################################################
############## Created by Devin Marks #####################
############# Spikefish Solutions Inc. ####################
###########################################################

# This file is part of Pointix
# Copyright (C) 2020 Spikefish Solutions

# Pointix is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# Pointix is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with Pointix.  If not, see <https://www.gnu.org/licenses/>.

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
        arguements = dict(opts)
        try:
            if arguements['-d'] != False:
                isMDS = True
        except:
            isMDS = False
    except getopt.GetoptError:
        print('usage: main.py -c <MDSIP> -d <domain> -z <ZABBIXURL> -s <SNMPVERSION(2 or 3)>')
        return
    
    # Initiate the Pointix object
    if isMDS == True:
        pointix = Pointix(arguements['-c'], arguements['-z'], arguements['-s'], arguements['-d'])
    elif isMDS == False:
        pointix = Pointix(arguements['-c'], arguements['-z'], arguements['-s'])

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
    if isMDS == True:
        pointix.getManageServers()
        pointix.authCheckPointDomain()
    
    pointix.getGateways()
    pointix.getClusters()

    # Add the devices to Zabbix
    if isMDS == True:
        pointix.addAllManagement()
        
    pointix.addAllGateways()
    pointix.addAllClusters()

    # Print the results of the devices adding to Zabbix
    pointix.printResults()
    pointix.logResults()


if __name__ == '__main__':
    main(sys.argv[1:])