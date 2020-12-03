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

import os
import yaml
from ipaddress import ip_address
from zabbix.api import ZabbixAPI
from cpapi import APIClient, APIClientArgs
from spikefish.spikefish_libs.logging import logging
from spikefish.checkpoint.apiv161.cp_apicalls import cpAuth


def severeHandle():
    os._exit(1)

class Pointix():

    def __init__(self, primaryMDS, cpDomain, zabbixURL, snmpVers):

        # Instantiate the lists for tracking results
        self.successGateways = []
        self.successClusters = []
        self.successManagement = []
        self.failedGateways = []
        self.failedClusters = []
        self.failedManagement = []
        self.ignoredGateways = []
        self.ignoredClusters = []
        self.ignoredManagement = []

        # Define the variables provided by the user
        self.primaryMDS = primaryMDS
        self.domain = cpDomain
        self.zabbix = zabbixURL
        self.snmpVersion = snmpVers


    def getGroups(self):
        # Reads the groups-templates file for the list of groups and templates to apply to the different types of hosts
        self.groupsList = {}
        self.templatesList = {}
        try:
            with open('groups-templates') as f:
                for line in f:
                    name = line.split(':')[0]
                    items = line.split(':')[1].strip('\n').split(',')
                    if 'Group' in name:
                        self.groupsList[name] = items
                    elif 'Template' in name:
                        self.templatesList[name] = items
        except Exception as e: 
            logging.logging('1', 'Unable to import the groups file', 'getGroups', e)


    def getFiles(self):
        self.overrideIP = {}
        self.ignoreIP = []
        self.daipIP = {}

        # Read the override IP file and create the dictionary
        try:
            with open('override') as f:
                for line in f:
                    (key,val) = line.split(':')
                    try:
                        ip_address(key)
                        ip_address(val)
                    except:
                        logging.logging('2', 'override line: ' + key + ':' + val + ' contains invalid IP address', 'getFiles')
                        continue
                    self.overrideIP[key] = val
            logging.logging('3', 'Successfully read override file', 'getFiles')
        except:
            logging.logging('3', 'Override file empty', 'getFiles')
            self.overrideIP = {}

        # Read the ignore MDS file
        try:
            with open('ignore-ip') as f:
                for line in f:
                    currentLine = line.rstrip('\n')
                    try:
                        ip_address(currentLine)
                    except:
                        logging.logging('2', 'ignore line: ' + currentLine + ' contains invalid IP address', 'getFiles')
                        continue
                    self.ignoreIP.append(currentLine)
            logging.logging('3', 'Successfully read ignore file', 'getFiles')
        except:
            logging.logging('3', 'Ignore file empty', 'getFiles')
            self.ignoreIP = []

        # Read the daip gateway file
        try:
            with open('daip') as f:
                for line in f:
                    (key,val) = line.split(':')
                    self.daipIP[key] = val
            logging.logging('3', 'Successfully read Daip file', 'getFiles')
        except:
            logging.logging('3', 'Daip file empty', 'getFiles')
            self.daipIP = {}
        return
    

    def getCreds(self):
        # Obtain the credentials needed for Authentication and SNMP
        yamlFile = yaml.load(open('application.yml'), Loader=yaml.FullLoader)
        try:
            self.cpUser = yamlFile['checkpoint']['username']
            self.cpPass = yamlFile['checkpoint']['password']
        except:
            self.cpUser = input('Please input the User for Check Point API: ')
            self.cpPass = input('Please input the Password for Check Point API: ')
        try:
            self.zbUser = yamlFile['zabbix']['username']
            self.zbPass = yamlFile['zabbix']['password']
        except:
            self.zbUser = input('Please input the User for Zabbix API: ')
            self.zbPass = input('Please input the Password for Zabbix API: ')
        if self.snmpVersion == '3':
            try:
                self.snmpUser = yamlFile['snmp3']['security']
                self.snmpAuth = yamlFile['snmp3']['auth']
                self.snmpPriv = yamlFile['snmp3']['priv']
            except:
                self.snmpUser = input('Please input the User for SNMPv3: ')
                self.snmpAuth = input('Please input the Auth phrase for SNMPv3: ')
                self.snmpPriv = input('Please input the Privacy phrase for SNMPv3: ')
        elif self.snmpVersion == '2':
            try:
                self.snmpCommunity = yamlFile['snmp2']['community']
            except:
                self.snmpCommunity = input('Please input the Community for SNMPv2: ')
        else:
            logging.logging('1', 'SNMP version not given', 'getCreds')

        logging.logging('3', 'Successfully imported credentials', 'getCreds')
        return


    def authZabbix(self):
        # Authenticate to the zabbix API
        self.zabbixClient = ZabbixAPI(url=self.zabbix, user=self.zbUser, password=self.zbPass)


    def authCheckPointGlobal(self):
        # Authenticate to the Check Point API in Global
        self.cpGlobalAPI = cpAuth(self.primaryMDS, self.cpUser, self.cpPass)
        return


    def authCheckPointDomain(self):
        # Authenticate to the Check Point API in the provided domain
        self.cpDomainAPI = cpAuth(self.primaryMDS, self.cpUser, self.cpPass, self.domain)
        return

    
    def addAllManagement(self):
        # Add all of the management servers to Zabbix
        for y in range(0, len(self.manageServersNames)):
            self.addManagementHost(self.manageServersNames[y], self.manageServersIP[y], self.manageServersInfo[y])


    def addAllGateways(self):
        # Obtain the info for gateways and create a host object in Zabbix with this info
        for y in range(0, len(self.gatewaysUid)):
            gatewayInfo = self.getGatewayInfo(self.gatewaysUid[y])
            self.addGatewayHost(self.gatewaysNames[y], gatewayInfo)


    def addAllClusters(self):
        # Obtain the info for the cluster and its members to create a Zabbix host for each member
        for y in range(0, len(self.clustersUid)):
            clusterInfo, clusterMembersNames, clusterIPs = self.getClusterInfo(self.clustersUid[y])
            self.addClusterHost(clusterInfo, clusterMembersNames, clusterIPs)


    def getManageServers(self):
        self.manageServersNames = []
        self.manageServersIP = []
        self.manageServersInfo = []

        # Obtain the Names and IP address of Management servers under the given domain
        apiDomainNamesTemp = self.cpGlobalAPI.api_call("show-domain", {'name': self.domain})

        if apiDomainNamesTemp.success == False:
            logging.logging('1', apiDomainNamesTemp.error_message, 'getManageServer')

        apiDomainNamesResult = apiDomainNamesTemp.data['servers']

        for y in range(0, len(apiDomainNamesResult)):
            apiDomainNamesResultTemp = apiDomainNamesResult[y]
            self.manageServersInfo.append(apiDomainNamesResultTemp)
            self.manageServersNames.append(apiDomainNamesResultTemp['name'])
            self.manageServersIP.append(apiDomainNamesResultTemp['ipv4-address'])
        
        logging.logging('3', 'Successfully pulled management servers from MDS', 'getManageServer')
        return


    def getGateways(self):
        # Queries the provided domain for all of its gateways
        self.gatewaysUid = []
        self.gatewaysNames = []

        gatewaysObjects = self.cpDomainAPI.api_call('show-simple-gateways', { })
        
        if gatewaysObjects.success == False:
            logging.logging('1', gatewaysObjects.error_message, 'getGateways')
        
        gatewaysResults = gatewaysObjects.data['objects']

        for x in range(0, len(gatewaysResults)):
            gatewaysResultsTemp = gatewaysResults[x]
            self.gatewaysUid.append(gatewaysResultsTemp['uid'])
            self.gatewaysNames.append(gatewaysResultsTemp['name'])

        logging.logging('3', 'Successfully pulled gateways from MDS', 'getGateways')
        return


    def getClusters(self):
        # Queries the provided domain for all of its clusters
        self.clustersUid = []
        self.clustersNames = []

        clustersObjects = self.cpDomainAPI.api_call('show-simple-clusters', { })
        
        if clustersObjects.success == False:
            logging.logging('1', clustersObjects.error_message, 'getClusters')
        
        clustersResults = clustersObjects.data['objects']

        for x in range(0, len(clustersResults)):
            clustersResultsTemp = clustersResults[x]
            self.clustersUid.append(clustersResultsTemp['uid'])
            self.clustersNames.append(clustersResultsTemp['name'])

        logging.logging('3', 'Successfully pulled clusters from MDS', 'getClusters')
        return


    def getGatewayInfo(self, gatewayUid):
        # Queries the Check Point API for information on a gateway uid

        gatewayInfo = self.cpDomainAPI.api_call('show-simple-gateway', {'uid': gatewayUid})

        if gatewayInfo.success == False:
            logging.logging('1', gatewayInfo.error_message, 'getGatewayInfo')
        
        name = gatewayInfo.data['name']
        
        logging.logging('3', f'Successfully pulled gateway info for {name}', 'getGatewayInfo')
        return(gatewayInfo)


    def getClusterInfo(self, clusterUid):
        # Queries the Check Point API for information on a cluster uid

        clusterMembersNames = []
        clusterMembersIP = []

        clusterInfo = self.cpDomainAPI.api_call('show-simple-cluster', {'uid': clusterUid})

        if clusterInfo.success == False:
            logging.logging('1', clusterInfo.error_message, 'getClusterInfo')

        clusterMembers = clusterInfo.data['cluster-members']
        for x in range(0, len(clusterMembers)):
            clusterMemberTemp = clusterMembers[x]
            clusterMembersNames.append(clusterMemberTemp['name'])
            clusterMembersIP.append(clusterMemberTemp['ip-address'])
        
        name = clusterInfo.data['name']
        
        logging.logging('3', f'Successfully pulled cluster info for {name}', 'getClusterInfo')
        return(clusterInfo, clusterMembersNames, clusterMembersIP)

    def getAllGroups(self):
        # Obtain the desired Zabbix groupIDs and templateIDs used for adding all gateways to Zabbix
        self.gatewayGroupID = self.getGroupID(self.groupsList['gatewayGroupName'], 'gatewayGroupID')
        self.gatewayTemplateID = self.getTemplateID(self.templatesList['gatewayTemplateName'], 'gatewayTemplateID')

        # Obtain the desired Zabbix groupID and templateID used for adding clusters to Zabbix 
        self.clusterGroupID = self.getGroupID(self.groupsList['clusterGroupName'], 'clusterGroupID')
        self.clusterTemplateID = self.getTemplateID(self.templatesList['clusterTemplateName'], 'clusterTemplateID')

        # Obtain the desired Zabbix groupID and templateID used for adding cluster members to Zabbix 
        self.clusterMembersGroupID = self.getGroupID(self.groupsList['clusterMembersGroupName'], 'clusterMembersGroupID')
        self.clusterMembersTemplateID = self.getTemplateID(self.templatesList['clusterMembersTemplateName'], 'clusterMembersTemplateID')

        # Obtain the desired Zabbix groupID and templateID used for adding MDS Management servers to Zabbix 
        self.managementGroupID = self.getGroupID(self.groupsList['managementGroupName'], 'managementGroupID')
        self.managementTemplateID = self.getTemplateID(self.templatesList['managementTemplateName'], 'managementTemplateID')

        # Obtain the desired Zabbix groupID and templateID used for adding CLM Log servers to Zabbix 
        self.logGroupID = self.getGroupID(self.groupsList['logGroupName'], 'logGroupID')
        self.logTemplateID = self.getTemplateID(self.templatesList['logTemplateName'], 'logTemplateID')


    def getGroupID(self, groupNames, group):
        # Takes a list of group names and returns a list of group IDs in the required format for the Zabbix API
        groupIDs = []
        
        for x in groupNames:
            groupID = False
            
            groupsRequest = self.zabbixClient.do_request('hostgroup.get', {'filter': {'name': [x]}})
            groupsResult = groupsRequest['result']
            groupInfo = groupsResult[0]

            if groupInfo['name'] == x:
                groupID = groupInfo['groupid']
                groupIDs.append({'groupid': groupID})
        
            if groupID == False:
                logging.logging('1', 'The given group ' + x + 'could not be found, please check this', 'getGroupID')

        logging.logging('3', f'Successfully pulled group IDs for {group}', 'getGroupID')
        return(groupIDs)


    def getTemplateID(self, templateName, template):
        # Takes a list of template names and returns a list of template IDs in the required format for the Zabbix API
        templateIDs = []
        
        for name in templateName:
            templateID = False

            templatesRequest = self.zabbixClient.do_request('template.get', {'filter': {'name': [name]}})
            templatesResult = templatesRequest['result']
            templateInfo = templatesResult[0]

            if templateInfo['name'] == name:
                templateID = templateInfo['templateid']
                templateIDs.append({'templateid': templateID})

            if templateID == False:
                logging.logging('1', 'The given template ' + name + 'could not be found, please check this', 'getTemplateID')

        logging.logging('3', f'Successfully pulled group IDs for {template}', 'getTemplateID')
        return(templateIDs)


    def addManagementHost(self, managementName, managementIP, managementInfo):
        managementGroups = []
        managementTemplates = []
        logGroups = []
        logTemplates = []

        if managementIP in self.ignoreIP:
            self.ignoredManagement.append(managementName)
            logging.logging('3', f'Ignored management host {managementName}', 'addManagementHost')
            return(True)

        #This is done for future use of adding version and hardware specific groups or templates
        for x in range(0, len(self.managementGroupID)):
            managementGroups.append(self.managementGroupID[x])

        for x in range(0, len(self.managementTemplateID)):
            managementTemplates.append(self.managementTemplateID[x])

        for x in range(0, len(self.logGroupID)):
            logGroups.append(self.logGroupID[x])

        for x in range(0, len(self.logTemplateID)):
            logTemplates.append(self.logTemplateID[x])

        if managementInfo['type'] == 'management server':
            try:
                self.zabbixClient.do_request('host.create', {'host': managementName, 'status': 0,'interfaces': [{'type': 2, 'main': 1, 'useip': 1, 'ip': managementIP, 'dns': '', 'port': '161', 'details': {'version': 3, 'bulk': 1, 'securityname': self.snmpUser, 'securitylevel': 2, 'authpassphrase': self.snmpAuth, 'authprotocol': 1, 'privpassphrase': self.snmpPriv, 'privprotocol': 1}}], 'groups': managementGroups, 'tags': [{'tag': 'Domain', 'value': self.domain}, {'tag': 'Vendor', 'value': 'Check Point'}], 'macros': [{'macro': '{$DOMAIN_NAME}', 'value': self.domain}, {'macro': '{$CMA_NAME}', 'value': managementName}], 'templates': managementTemplates, 'inventory_mode': 1, 'inventory': {'vendor': 'Check Point'}})
                #SNMPv2
                #self.zabbixClient.do_request('host.create', {'host': managementName, 'status': 0,'interfaces': [{'type': 2, 'main': 1, 'useip': 1, 'ip': managementIP, 'dns': '', 'port': '161', 'details': {'version': 2, 'bulk': 1, 'community': self.snmpCommunity}}], 'groups': managementGroups, 'tags': [{'tag': 'Domain', 'value': self.domain}, {'tag': 'Vendor', 'value': 'Check Point'}], 'macros': [{'macro': '{$DOMAIN_NAME}', 'value': self.domain}, {'macro': '{$CMA_NAME}', 'value': managementName}], 'templates': managementTemplates, 'inventory_mode': 1, 'inventory': {'vendor': 'Check Point'}})
                
                logging.logging('3', f'Successfully added management host {managementName} to Zabbix', 'addManagementHost')
                self.successManagement.append(managementName)
            except Exception as e:
                logging.logging('2', f'Failed to add management host {managementName} to Zabbix', 'addManagementHost', e)
                self.failedManagement.append(managementName)
        elif managementInfo['type'] == 'log server':
            try:
                if self.snmpVersion == '3':
                    self.zabbixClient.do_request('host.create', {'host': managementName, 'status': 0,'interfaces': [{'type': 2, 'main': 1, 'useip': 1, 'ip': managementIP, 'dns': '', 'port': '161', 'details': {'version': 3, 'bulk': 1, 'securityname': self.snmpUser, 'securitylevel': 2, 'authpassphrase': self.snmpAuth, 'authprotocol': 1, 'privpassphrase': self.snmpPriv, 'privprotocol': 1}}], 'groups': logGroups, 'tags': [{'tag': 'Domain', 'value': self.domain}, {'tag': 'Vendor', 'value': 'Check Point'}], 'macros': [{'macro': '{$DOMAIN_NAME}', 'value': self.domain}, {'macro': '{$CMA_NAME}', 'value': managementName}], 'templates': logTemplates, 'inventory_mode': 1, 'inventory': {'vendor': 'Check Point'}})
                elif self.snmpVersion == '2':
                    self.zabbixClient.do_request('host.create', {'host': managementName, 'status': 0,'interfaces': [{'type': 2, 'main': 1, 'useip': 1, 'ip': managementIP, 'dns': '', 'port': '161', 'details': {'version': 2, 'bulk': 1, 'community': self.snmpCommunity}}], 'groups': logGroups, 'tags': [{'tag': 'Domain', 'value': self.domain}, {'tag': 'Vendor', 'value': 'Check Point'}], 'macros': [{'macro': '{$DOMAIN_NAME}', 'value': self.domain}, {'macro': '{$CMA_NAME}', 'value': managementName}], 'templates': logTemplates, 'inventory_mode': 1, 'inventory': {'vendor': 'Check Point'}})
                
                logging.logging('3', f'Successfully added log host {managementName} to Zabbix', 'addManagementHost')
                self.successManagement.append(managementName)
            except Exception as e:
                logging.logging('2', f'Failed to add log host {managementName} to Zabbix', 'addManagementHost', e)
                self.failedManagement.append(managementName)

        return(True)


    def addGatewayHost(self, gatewayName, gatewayInfo):
        # Takes a gateway and adds it to Zabbix as a host

        # Check to see if the gateway is in the ignore IP list, if so then return the function and add to ignored list
        if gatewayInfo.data['ipv4-address'] in self.ignoreIP:
            self.ignoredGateways.append(gatewayName)
            logging.logging('3', f'Ignored gateway host {gatewayName}', 'addGatewayHost')
            return(True)

        gatewayGroups = []
        gatewayTemplates = []
        gatewayStatus = 0

        domainObject = gatewayInfo.data['domain']
        domainName = domainObject['name']
        
        #This is done for future use of adding version and hardware specific groups or templates
        for x in range(0, len(self.gatewayGroupID)):
            gatewayGroups.append(self.gatewayGroupID[x])

        for x in range(0, len(self.gatewayTemplateID)):
            gatewayTemplates.append(self.gatewayTemplateID[x])
        
        # Checks if the gateway should be disabled in Zabbix because it is in staging
        if gatewayInfo.data['comments'].lower() == 'disabled':
            gatewayStatus = 1

        # Checks the override IP dictionary for a match
        if gatewayInfo.data['ipv4-address'] in self.overrideIP:
            gatewayInfo.data['ipv4-address'] = self.overrideIP[gatewayInfo.data['ipv4-address']]

        # Adds the gateway to Zabbix
        try:
            # Check the daip name dictionary for a match
            if gatewayName in self.daipIP:
                gatewayInfo.data['ipv4-address'] = self.daipIP[gatewayName]
                if self.snmpVersion == '3':
                    self.zabbixClient.do_request('host.create', {'host': gatewayName, 'status': gatewayStatus, 'interfaces': [{'type': 2, 'main': 1, 'useip': 0, 'ip': '', 'dns': gatewayInfo.data['ipv4-address'], 'port': '161', 'details': {'version': 3, 'bulk': 1, 'securityname': self.snmpUser, 'securitylevel': 2, 'authpassphrase': self.snmpAuth, 'authprotocol': 1, 'privpassphrase': self.snmpPriv, 'privprotocol': 1}}], 'groups': gatewayGroups, 'tags': [{'tag': 'Domain', 'value': domainName}, {'tag': 'Vendor', 'value': 'Check Point'}], 'macros': [{'macro': '{$DOMAIN_NAME}', 'value': domainName}], 'templates': gatewayTemplates, 'inventory_mode': 1, 'inventory': {'location': domainName, 'vendor': 'Check Point'}})
                elif self.snmpVersion == '2':
                    self.zabbixClient.do_request('host.create', {'host': gatewayName, 'status': gatewayStatus, 'interfaces': [{'type': 2, 'main': 1, 'useip': 0, 'ip': '', 'dns': gatewayInfo.data['ipv4-address'], 'port': '161', 'details': {'version': 2, 'bulk': 1, 'community': self.snmpCommunity}}], 'groups': gatewayGroups, 'tags': [{'tag': 'Domain', 'value': domainName}, {'tag': 'Vendor', 'value': 'Check Point'}], 'macros': [{'macro': '{$DOMAIN_NAME}', 'value': domainName}], 'templates': gatewayTemplates, 'inventory_mode': 1, 'inventory': {'location': domainName, 'vendor': 'Check Point'}})
            elif gatewayInfo.data['dynamic-ip'] == 'true':
                logging.logging('2', f'DAIP gateway {gatewayName} not found in the daip file, not adding to Zabbix', 'addGatewayHost')
                self.failedGateways.append(gatewayName)
                return(True)
            else:
                if self.snmpVersion == '3':
                    self.zabbixClient.do_request('host.create', {'host': gatewayName, 'status': gatewayStatus, 'interfaces': [{'type': 2, 'main': 1, 'useip': 1, 'ip': gatewayInfo.data['ipv4-address'], 'dns': '', 'port': '161', 'details': {'version': 3, 'bulk': 1, 'securityname': self.snmpUser, 'securitylevel': 2, 'authpassphrase': self.snmpAuth, 'authprotocol': 1, 'privpassphrase': self.snmpPriv, 'privprotocol': 1}}], 'groups': gatewayGroups, 'tags': [{'tag': 'Domain', 'value': domainName}, {'tag': 'Vendor', 'value': 'Check Point'}], 'macros': [{'macro': '{$DOMAIN_NAME}', 'value': domainName}], 'templates': gatewayTemplates, 'inventory_mode': 1, 'inventory': {'location': domainName, 'vendor': 'Check Point'}})
                elif self.snmpVersion == '2':
                    self.zabbixClient.do_request('host.create', {'host': gatewayName, 'status': gatewayStatus, 'interfaces': [{'type': 2, 'main': 1, 'useip': 1, 'ip': gatewayInfo.data['ipv4-address'], 'dns': '', 'port': '161', 'details': {'version': 2, 'bulk': 1, 'community': self.snmpCommunity}}], 'groups': gatewayGroups, 'tags': [{'tag': 'Domain', 'value': domainName}, {'tag': 'Vendor', 'value': 'Check Point'}], 'macros': [{'macro': '{$DOMAIN_NAME}', 'value': domainName}], 'templates': gatewayTemplates, 'inventory_mode': 1, 'inventory': {'location': domainName, 'vendor': 'Check Point'}})
            
            logging.logging('3', f'Successfully added gateway host {gatewayName} to Zabbix', 'addGatewayHost')
            self.successGateways.append(gatewayName)
        except Exception as e:
            logging.logging('2', f'Failed to add gateway host {gatewayName} to Zabbix', 'addGatewayHost', e)
            self.failedGateways.append(gatewayName)

        return(True)


    def addClusterHost(self, clusterInfo, clusterMembersNames, clusterMembersIP):
        # Takes a cluster and adds each member to Zabbix as their own hosts.  The host object will have the VIP as a secondary SNMP interface

        sep = '_._._'
        clusterGroups = []
        clusterTemplates = []
        clusterMembersGroups = []
        clusterMembersTemplates = []
        clusterStatus = 0
        
        clusterNameFull = clusterInfo.data['name']
        clusterName= clusterNameFull.split(sep, 1)[0]
        
        if clusterInfo.data['ipv4-address'] in self.ignoreIP:
            self.ignoredClusters.append(clusterName)
            logging.logging('3', f'Ignored cluster {clusterName}', 'addGatewayHost')
            return(True)

        domainObject = clusterInfo.data['domain']
        domainName = domainObject['name']

        #This is done for future use of adding version and hardware specific groups or templates
        for x in range(0, len(self.clusterGroupID)):
            clusterGroups.append(self.clusterGroupID[x])

        for x in range(0, len(self.clusterTemplateID)):
            clusterTemplates.append(self.clusterTemplateID[x])

        for x in range(0, len(self.clusterMembersGroupID)):
            clusterMembersGroups.append(self.clusterMembersGroupID[x])

        for x in range(0, len(self.clusterMembersTemplateID)):
            clusterMembersTemplates.append(self.clusterMembersTemplateID[x])
        
        # Checks the override dictionary for a match on the VIP address
        if clusterInfo.data['ipv4-address'] in self.overrideIP:
            clusterInfo.data['ipv4-address'] = self.overrideIP[clusterInfo.data['ipv4-address']]
        
        if clusterInfo.data['comments'].lower() == 'disabled':
            clusterStatus = 1
        
        try:
            for x in range(0, len(clusterMembersNames)):
                # Checks the override dictionary for a match on the members IP
                if clusterMembersIP[x] in self.overrideIP:
                    clusterMembersIP[x] = self.overrideIP[clusterMembersIP[x]]
                
                # Adds the cluster members to Zabbix
                memberName = clusterMembersNames[x].split(sep, 1)[0]

                # Check the daip name dictionary for a match
                if memberName in self.daipIP:
                    clusterMembersIP[x] = self.daipIP[memberName]
                    if self.snmpVersion == '3':
                        self.zabbixClient.do_request('host.create', {'host': memberName, 'status': clusterStatus, 'interfaces': [{'type': 2, 'main': 1, 'useip': 0, 'ip': '', 'dns': clusterMembersIP[x], 'port': '161', 'details': {'version': 3, 'bulk': 1, 'securityname': self.snmpUser, 'securitylevel': 2, 'authpassphrase': self.snmpAuth, 'authprotocol': 1, 'privpassphrase': self.snmpPriv, 'privprotocol': 1}}], 'groups': clusterMembersGroups, 'tags': [{'tag': 'Cluster Name', 'value': clusterName}, {'tag': 'Domain', 'value': domainName}, {'tag': 'Vendor', 'value': 'Check Point'}], 'macros': [{'macro': '{$DOMAIN_NAME}', 'value': domainName}], 'templates': clusterMembersTemplates, 'inventory_mode': 1, 'inventory': {'location': domainName, 'vendor': 'Check Point'}})
                    elif self.snmpVersion == '2':
                        self.zabbixClient.do_request('host.create', {'host': memberName, 'status': clusterStatus, 'interfaces': [{'type': 2, 'main': 1, 'useip': 0, 'ip': '', 'dns': clusterMembersIP[x], 'port': '161', 'details': {'version': 2, 'bulk': 1, 'community': self.snmpCommunity}}], 'groups': clusterMembersGroups, 'tags': [{'tag': 'Cluster Name', 'value': clusterName}, {'tag': 'Domain', 'value': domainName}, {'tag': 'Vendor', 'value': 'Check Point'}], 'macros': [{'macro': '{$DOMAIN_NAME}', 'value': domainName}], 'templates': clusterMembersTemplates, 'inventory_mode': 1, 'inventory': {'location': domainName, 'vendor': 'Check Point'}})
                else:
                    if self.snmpVersion == '3':
                        self.zabbixClient.do_request('host.create', {'host': memberName, 'status': clusterStatus, 'interfaces': [{'type': 2, 'main': 1, 'useip': 1, 'ip': clusterMembersIP[x], 'dns': '', 'port': '161', 'details': {'version': 3, 'bulk': 1, 'securityname': self.snmpUser, 'securitylevel': 2, 'authpassphrase': self.snmpAuth, 'authprotocol': 1, 'privpassphrase': self.snmpPriv, 'privprotocol': 1}}], 'groups': clusterMembersGroups, 'tags': [{'tag': 'Cluster Name', 'value': clusterName}, {'tag': 'Domain', 'value': domainName}, {'tag': 'Vendor', 'value': 'Check Point'}], 'macros': [{'macro': '{$DOMAIN_NAME}', 'value': domainName}], 'templates': clusterMembersTemplates, 'inventory_mode': 1, 'inventory': {'location': domainName, 'vendor': 'Check Point'}})
                    elif self.snmpVersion == '2':
                        self.zabbixClient.do_request('host.create', {'host': memberName, 'status': clusterStatus, 'interfaces': [{'type': 2, 'main': 1, 'useip': 1, 'ip': clusterMembersIP[x], 'dns': '', 'port': '161', 'details': {'version': 2, 'bulk': 1, 'community': self.snmpCommunity}}], 'groups': clusterMembersGroups, 'tags': [{'tag': 'Cluster Name', 'value': clusterName}, {'tag': 'Domain', 'value': domainName}, {'tag': 'Vendor', 'value': 'Check Point'}], 'macros': [{'macro': '{$DOMAIN_NAME}', 'value': domainName}], 'templates': clusterMembersTemplates, 'inventory_mode': 1, 'inventory': {'location': domainName, 'vendor': 'Check Point'}})
                logging.logging('3', f'Successfully added cluster member host {memberName}', 'addClusterHost')

            # Check the daip name dictionary for a match and adds the cluster to zabbix
            if clusterName in self.daipIP:
                clusterInfo.data['ipv4-address'] = self.daipIP[clusterName]
                if self.snmpVersion == '3':
                    self.zabbixClient.do_request('host.create', {'host': clusterName, 'status': clusterStatus, 'interfaces': [{'type': 2, 'main': 1, 'useip': 0, 'ip': '', 'dns': clusterInfo.data['ipv4-address'], 'port': '161', 'details': {'version': 3, 'bulk': 1, 'securityname': self.snmpUser, 'securitylevel': 2, 'authpassphrase': self.snmpAuth, 'authprotocol': 1, 'privpassphrase': self.snmpPriv, 'privprotocol': 1}}], 'groups': clusterGroups, 'tags': [{'tag': 'Cluster Name', 'value': clusterName}, {'tag': 'Domain', 'value': domainName}, {'tag': 'Vendor', 'value': 'Check Point'}], 'macros': [{'macro': '{$DOMAIN_NAME}', 'value': domainName}], 'templates': clusterTemplates, 'inventory_mode': 1, 'inventory': {'location': domainName, 'vendor': 'Check Point'}})
                elif self.snmpVersion == '2':
                    self.zabbixClient.do_request('host.create', {'host': clusterName, 'status': clusterStatus, 'interfaces': [{'type': 2, 'main': 1, 'useip': 0, 'ip': '', 'dns': clusterInfo.data['ipv4-address'], 'port': '161', 'details': {'version': 2, 'bulk': 1, 'community': self.snmpCommunity}}], 'groups': clusterGroups, 'tags': [{'tag': 'Cluster Name', 'value': clusterName}, {'tag': 'Domain', 'value': domainName}, {'tag': 'Vendor', 'value': 'Check Point'}], 'macros': [{'macro': '{$DOMAIN_NAME}', 'value': domainName}], 'templates': clusterTemplates, 'inventory_mode': 1, 'inventory': {'location': domainName, 'vendor': 'Check Point'}})
            else:
                if self.snmpVersion == '3':
                    self.zabbixClient.do_request('host.create', {'host': clusterName, 'status': clusterStatus, 'interfaces': [{'type': 2, 'main': 1, 'useip': 1, 'ip': clusterInfo.data['ipv4-address'], 'dns': '', 'port': '161', 'details': {'version': 3, 'bulk': 1, 'securityname': self.snmpUser, 'securitylevel': 2, 'authpassphrase': self.snmpAuth, 'authprotocol': 1, 'privpassphrase': self.snmpPriv, 'privprotocol': 1}}], 'groups': clusterGroups, 'tags': [{'tag': 'Cluster Name', 'value': clusterName}, {'tag': 'Domain', 'value': domainName}, {'tag': 'Vendor', 'value': 'Check Point'}], 'macros': [{'macro': '{$DOMAIN_NAME}', 'value': domainName}], 'templates': clusterTemplates, 'inventory_mode': 1, 'inventory': {'location': domainName, 'vendor': 'Check Point'}})
                elif self.snmpVersion == '2':
                    self.zabbixClient.do_request('host.create', {'host': clusterName, 'status': clusterStatus, 'interfaces': [{'type': 2, 'main': 1, 'useip': 1, 'ip': clusterInfo.data['ipv4-address'], 'dns': '', 'port': '161', 'details': {'version': 2, 'bulk': 1, 'community': self.snmpCommunity}}], 'groups': clusterGroups, 'tags': [{'tag': 'Cluster Name', 'value': clusterName}, {'tag': 'Domain', 'value': domainName}, {'tag': 'Vendor', 'value': 'Check Point'}], 'macros': [{'macro': '{$DOMAIN_NAME}', 'value': domainName}], 'templates': clusterTemplates, 'inventory_mode': 1, 'inventory': {'location': domainName, 'vendor': 'Check Point'}})
            
            logging.logging('3', f'Successfully added cluster host {clusterName}', 'addClusterHost')
            
            self.successClusters.append(clusterName)

        except Exception as e:
            logging.logging('2', f'Failed to add cluster {clusterName}', 'addClusterHost', e)
            self.failedClusters.append(clusterName)
        
        return(True)


    def printResults(self):
        # Prints the results of adding the hosts to Zabbix
        print('\nThe following Gateways have successfully been added to Zabbix:')
        print(self.successGateways)

        print('\nThe following Gateways have failed to add to Zabbix:')
        print(self.failedGateways)
        
        print('\nThe following Gateways were ignored due to being in ignore-ip:')
        print(self.ignoredGateways)

        print('\nThe following Clusters have successfully been added to Zabbix:')
        print(self.successClusters)

        print('\nThe following Clusters have failed to add to Zabbix:')
        print(self.failedClusters)

        print('\nThe following Clusters were ignored due to being in ignore-ip:')
        print(self.ignoredClusters)

        print('\nThe following CMA Management servers have successfully been added to Zabbix:')
        print(self.successManagement)

        print('\nThe following CMA Management Servers have failed to add to Zabbix:')
        print(self.failedManagement)

        print('\nThe following CMA Management Servers were ignored due to being in ignore-ip:')
        print(self.ignoredManagement)

    def logResults(self):
        # Outputs the results of adding the hosts to Zabbix into the log file
        loggingFile = open("logging.txt", "a")
        loggingFile.write('\nThe following Gateways have successfully been added to Zabbix:')
        loggingFile.write(f'{self.successGateways}')

        loggingFile.write('\nThe following Gateways have failed to add to Zabbix:')
        loggingFile.write(f'{self.failedGateways}')

        loggingFile.write('\nThe following Gateways were ignored due to being in ignore-ip:')
        loggingFile.write(f'{self.ignoredGateways}')

        loggingFile.write('\nThe following Clusters have successfully been added to Zabbix:')
        loggingFile.write(f'{self.successClusters}')

        loggingFile.write('\nThe following Clusters have failed to add to Zabbix:')
        loggingFile.write(f'{self.failedClusters}')

        loggingFile.write('\nThe following Clusters were ignored due to being in ignore-ip:')
        loggingFile.write(f'{self.ignoredClusters}')

        loggingFile.write('\nThe following CMA Management servers have successfully been added to Zabbix:')
        loggingFile.write(f'{self.successManagement}')

        loggingFile.write('\nThe following CMA Management Servers have failed to add to Zabbix:')
        loggingFile.write(f'{self.failedManagement}')

        loggingFile.write('\nThe following CMA Management Servers were ignored due to being in ignore-ip:')
        loggingFile.write(f'{self.ignoredManagement}')