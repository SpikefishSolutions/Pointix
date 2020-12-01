from spikefish.spikefish_libs.logging import logging
from cpapi import APIClient, APIClientArgs


def cpAuth(serverIP, cpUser, cpPass, domainName=0):
    #Authenticate to Check Point Server
    client_args = APIClientArgs(server=serverIP)
    client = APIClient(client_args)
    try:
        if domainName == 0:
            login = client.login(cpUser, cpPass)
        else:
            login = client.login(cpUser, cpPass, domain=domainName)
        logging.logging('3', "Successfully authenticated to CP API", "cpAuth")
    except:
        logging.logging('1', "Failed to authenticate to CP API", "cpAuth")
    return(client)
    

def discardNew(client):

    if client == 0:
        logging.logging('3', "No changes to discard", "discardNew")
        exit(0)

    apiDiscard = client.api_call("discard", { })
    print("Session discarded due to error importing object, check errors and try again")
    if apiDiscard.success == False:
        logging.logging('2', apiDiscard.error_message.replace("\n", " "), "discardNew")
        exit(0)
    else:
        logging.logging('3', "Successfully discarded changes", "discardNew")
        exit(0)


def publishNew(client):

    apiPublish = client.api_call("publish", { })

    if apiPublish.success == False:
        logging.logging('1', apiPublish.error_message.replace("\n", " "), "publishNew")
        return()
    else:
        print("Session published, please confirm objects have been imported properly")
        logging.logging('3', "Successfully published changes, exiting", "publishNew")
        exit(1)


def getPolicies(client):

    apiPoliciesTemp = client.api_call("show-access-layers", { })

    if apiPoliciesTemp.success == False:
        logging.logging('1', apiPoliciesTemp.error_message.replace("\n", " "), "getPolicies")
        return()
    else:
        logging.logging('3', "Successfully pulled policies list", "getPolicies")
        apiPoliciesResults = apiPoliciesTemp.data['access-layers']
        return(apiPoliciesResults)


def getPackage(client, PackageName):

    apiPackageTemp = client.api_call("show-package", {'name': PackageName})

    if apiPackageTemp.success == False:
        logging.logging('1', apiPackageTemp.error_message.replace("\n", " "), f"getPackage for Package {PackageName}")
        return()
    else:
        logging.logging('3', "Successfully pulled Package", f"getPackage for Package {PackageName}")
        apiPackageResults = apiPackageTemp.data
        return(apiPackageResults)


def getRulebase(client, policyName):

    apiPolicyTemp = client.api_call("show-access-rulebase", {'name': policyName, 'limit': 500})

    if apiPolicyTemp.success == False:
        logging.logging('1', apiPolicyTemp.error_message.replace("\n", " "), f"getPolicy for policy {policyName}")
        return()
    else:
        logging.logging('3', "Successfully pulled policy", f"getPolicy for policy {policyName}")
        apiPolicyResults = apiPolicyTemp.data
        return(apiPolicyResults)


def getObject(client, objectUid):

    apiObjectTemp = client.api_call("show-object", {'uid': objectUid})

    if apiObjectTemp.success == False:
        logging.logging('2', apiObjectTemp.error_message.replace("\n", " "), f"getObject for object {objectUid}")
        return()
    else:
        logging.logging('3', f"Successfully pulled object {objectUid}", "getObject")
        apiObjectResults = apiObjectTemp.data['object']
        return(apiObjectResults)


def getAnything(client, objectInfo):

    apiObject = client.api_call(f"show-{objectInfo['type']}", {'name': objectInfo['name']})

    if apiObject.success == False:
        logging.logging('2', apiObject.error_message.replace("\n", " "), f"getAnything for object {objectInfo['name']}")
        return()
    else:
        logging.logging('3', f"Successfully pulled object {objectInfo['name']}", "getAnything")
        apiObjectResults = apiObject.data
        return(apiObjectResults)