## What is Pointix?
Pointix is a tool for populating Zabbix with all of the Check Point devices in your network.  Pointix uses the Check Point API to obtain all of the devices on the network and the Zabbix API for adding all of the devices to be monitored.

Pointix will query a Check Point Primary MDS, and a particular domain within that MDS, and add the standalone gateways, clusters, MDS management servers, and management log servers to zabbix. For all of the added hosts, the script will automatically add the specified groups and templates to that host in Zabbix. Pointix can also disable a gateway in Zabbix if the comment in Check Point for that device is 'disabled'. Pointix will log to 'logging.txt' in the same directory as the script is run.

**Tagging and inventory**<br>
Pointix will apply the following tags to the hosts when added to Zabbix:
* Vendor: Will always be 'Check Point' since this is only made to operate with Check Point
* Domain: The domain name the device was from, this is for sorting through hosts
* Cluster Name: The name of the cluster from the MDS, used for finding the hosts for a particular cluster
* Inventory 'Location': Currently populated with the domain name for use in creating reports
* Inventory 'Vendor': Will always be 'Check Point' since this is only made to operate with Check Point

**Check Point Clusters**<br>
When Pointix adds a cluster to Zabbix, it will add 3 hosts.  One host for each cluster member, and one host that uses the cluster VIP.
The reason for this is so that you can monitor the active firewall with Zabbix or view information on the primary firewall without having to identify which of the pair is active.

**Pointix Files:**
* override
  * This is a file of override IP address, so if you want the monitoring IP for a device to be different than what the Check Point API responds with
  * In the below example a gateway with the IP 192.168.100.1 will be put into Zabbix with the IP 10.10.10.1
  * Example format: 
```
192.168.100.1:10.10.10.1
```
* ignore-ip
  * This file is used to ignore any device with the given IP address.  The IP can be of a management server, management log server, gateway, cluster, or cluster member.
  * The format for this file is just a list of IP seperated by new lines.
  * Example format: 
```
192.168.100.2
192.168.100.3
```
* daip
  * DAIP gateways will often change their IP address so it does not make sense to place their current IP address into Zabbix.  Instead the 'daip' file is a list of DAIP GW names and the domain names that you want to place into Zabbix for monitoring.  This can also be used with non-daip gateways if you want to monitor certain firewalls by their domain name.
  * In the below example a DAIP GW named 'daip-gw' will have the domain example.local.com in Zabbix for monitoring.  And a DAIP GW named 'another-daip-gw' will have the domain anotherexample.local.com in zabbix for monitoring.
  * Example format:
```
daip-gw example.local.com
another-daip-gw anotherexample.local.com
```
* application.yml
  * This is the YAML file where credentials are stored for the Check Point and Zabbix API calls and SNMP credentials.  This file should only be viewable by the OS user used to run the tool.  If this file is not present, or if some credentials are missing, the user will be asked for the missing credentials on run.  I chose to use a macro for my SNMP credentials which is stored as a secret on a macro that gets applied to all of my devices.
  * Example format:
```
checkpoint:
        username: admin
        password: examplepass

zabbix:
        username: Admin
        password: examplepass

snmp2:
        community: '{$SNMP2_COMMUNITY}'

snmp3:
        security: '{$SNMPV3_SECURITY}'
        auth: '{$SNMPV3_AUTH}'
        priv: '{$SNMPV3_PRIV}'
```
* groups-templates
  * This file is where the lists go for the groups and templates to apply to the different types of hosts added to Zabbix.  Do not change anything before the ':' on each line, simply place the list of groups and templates after the ':' seperated by commas.
  * Example format:
```
gatewayGroupName:Check Point Standalone Gateways
gatewayTemplateName:Check Point Standalone Gateways,Check Point Firewalls,Check Point Generic Device
clusterGroupName:Check Point Cluster
clusterTemplateName:Check Point Cluster,Check Point Firewalls,Check Point Generic Device
```

## Running the Tool
#### 1. Install the Check Point Python SDK and the py-zabbix Python module.

Links for these modules:
* Check Point API: [Here](https://github.com/CheckPointSW/cp_mgmt_api_python_sdk)
* py-zabbix: [Here](https://pypi.org/project/py-zabbix/)

(Note: You can just include the folder 'cpapi' in the main directory for this project.)

#### 3. Create and edit the necessary files and run the tool
Make sure that you have filled out the 'groups-templates' file as explained above, the list of DAIP gateways in the 'daip' file if there are any in the environment, as well as the 'override' and 'ignore-ip' files if desired.  As long as 'groups-templates' is filled out, the code can be executed as follows:
```
python3 main.py -c <MDSIP> -d <domain> -z <ZABBIXURL> -s <SNMPVERSION(2 or 3)>
python3 main.py -c 10.10.10.10 -d example_domain -z http://10.10.10.11/zabbix/ -s 3
python3 main.py -h
```

#### 4. Logging
After the script runs, it will output all of the hosts that were added, that were ignored, and that failed.  Everything is also logged to the 'logging.txt' file to determine why particular hosts failed to add to zabbix. Informative is used for successful actions, warnings are used for hosts that failed to add, and severe warnings are reserved for issues that will cause the code to stop executing.  Please refer to the logging file when something fails, and if you believe it is due to the script in some way, please provide the lines you believe are causing the issue.
