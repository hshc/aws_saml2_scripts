#!/usr/bin/env python

#Note: Requires Python 3.3 or higher
 
import sys
import boto3
import requests 
import getpass 
import configparser 
import base64 
import xml.etree.ElementTree as ET 
import re
from bs4 import BeautifulSoup
from os.path import expanduser 
from urllib.parse import urlparse, urlunparse 

 
##########################################################################
# Variables 
 
# region: The default AWS region that this script will connect 
# to for all API calls 
region = 'eu-west-3'
 
# output format: The AWS CLI output format that will be configured in the 
# saml profile (affects subsequent CLI calls) 
outputformat = 'json'
 
# awsconfigfile: The file where this script will store the temp 
# credentials under the saml profile 
awsconfigfile = '/.aws/credentials'
 
# SSL certificate verification: Whether or not strict certificate 
# verification is done, False should only be used for dev/test 
sslverification = False
# sslverification = True

# idpentryurl: The initial URL that starts the authentication process. 
# idpentryurl = 'https://<fqdn>/adfs/ls/IdpInitiatedSignOn.aspx?loginToRp=urn:amazon:webservices'
idpentryurl = 'https://sts.r7b1envenue.com/adfs/ls/idpinitiatedsignon.aspx?loginToRp=urn:amazon:webservices&RedirectToIdentityProvider=AD+AUTHORITY'
# idpentryurl = 'https://sts.b1envenue.com/adfs/ls/idpinitiatedsignon.aspx?loginToRp=urn:amazon:webservices&RedirectToIdentityProvider=AD+AUTHORITY'

userAgent = "Mozilla/5.0 (X11; CentOS; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0"
http_proxy  = "http://127.0.0.1:8080"
https_proxy = "https://127.0.0.1:8080"

proxyDict = {
    "http"  : http_proxy,
    "https" : https_proxy
}

# useMfa: True if the SAML authentication process requires MFA
useMfa = False

# selectRole: True if you want to select only one role to be append to aws/credentials, if False add all the roles
selectRole = False


# Uncomment to enable low level debugging
# logging.basicConfig(level=logging.DEBUG)

# MFA Verification Option choice
# verificationOption0 = mobile app
# verificationOption1 = phone call
# verificationOption2 = sms
verificationOption = 'verificationOption0'

##########################################################################

# Get the federated credentials from the user
print("Username:", end=' ')
username = input()
password = getpass.getpass()

print('')

# Initiate session handler 
session = requests.Session()

session.headers['User-Agent'] = userAgent
# uncomment following line to use proxy
# session.proxies = proxyDict


# # Programatically get the SAML assertion
# Opens the initial IdP url and follows all of the HTTP302 redirects, and
# gets the resulting login page

##########
# Http call 1

response = session.get(idpentryurl, verify=sslverification)
# Debug the response if needed
# print (response.text)
soup = BeautifulSoup(response.text)

# Capture the idpauthformsubmiturl, which is the final url after all the 302s
idpauthformsubmiturl = response.url

# Parse the response and extract all the necessary values
# in order to build a dictionary of all of the form values the IdP expects
payload = {}

for inputtag in soup.find_all(re.compile('(INPUT|input)')):
    name = inputtag.get('name','')
    value = inputtag.get('value','')
    if "user" in name.lower():
        #Make an educated guess that this is the right field for the username
        payload[name] = username
    elif "email" in name.lower():
        #Some IdPs also label the username field as 'email'
        payload[name] = username
    elif "pass" in name.lower():
        #Make an educated guess that this is the right field for the password
        payload[name] = password
    else:
        #Simply populate the parameter with the existing value (picks up hidden fields in the login form)
        payload[name] = value

# Set our AuthMethod to Form-based auth because the code above sees two values
# for authMethod and the last one is wrong
payload['AuthMethod'] = 'FormsAuthentication'

# Debug the parameter payload if needed
# Use with caution since this will print sensitive output to the screen

print(payload)

# Some IdPs don't explicitly set a form action, but if one is set we should
# build the idpauthformsubmiturl by combining the scheme and hostname
# from the entry url with the form action target
# If the action tag doesn't exist, we just stick with the
# idpauthformsubmiturl above
for inputtag in soup.find_all(re.compile('(FORM|form)')):
    action = inputtag.get('action')
    loginid = inputtag.get('id')
    if (action and loginid == "loginForm"):
        parsedurl = urlparse(idpentryurl)
        idpauthformsubmiturl = parsedurl.scheme + "://" + parsedurl.netloc + action

print(idpauthformsubmiturl)
print('')





#########
# Http call 2

# Performs the submission of the IdP login form with the above post data
response = session.post(idpauthformsubmiturl, data=payload, verify=sslverification)
# Debug the response if needed
# print (response.text)
soup = BeautifulSoup(response.text)
payload = {}


####################################################################################
#                 MFA                                                              #
####################################################################################
if useMfa:

    # MFA Step 1 - If you have MFA Enabled, there are two additional steps to authenticate
    # Choose a verification option and reload the page

    # Capture the idpauthformsubmiturl, which is the final url after all the 302s
    mfaurl = response.url

    for inputtag in soup.find_all(re.compile('(INPUT|input)')):
        name = inputtag.get('name','')
        value = inputtag.get('value','')
        #Simply populate the parameter with the existing value (picks up hidden fields in the login form)
        payload[name] = value

    # Set mfa auth type here...
    payload['__EVENTTARGET'] = verificationOption
    payload['AuthMethod'] = 'AzureMfaServerAuthentication'


    #########
    # Http call 2 BIS

    response = session.post(mfaurl, data=payload, verify=sslverification)
    # Debug the response if needed
    # print (response.text)
    soup = BeautifulSoup(response.text)
    payload = {}


    # MFA Step 2 - Fire the form and wait for verification
    for inputtag in soup.find_all(re.compile('(INPUT|input)')):
        name = inputtag.get('name','')
        value = inputtag.get('value','')
        #Simply populate the parameter with the existing value (picks up hidden fields in the login form)
        payload[name] = value
    payload['AuthMethod'] = 'AzureMfaServerAuthentication'
##################################################################################






#################### Get the roles of SAMLResponse
assertion = ''

# Overwrite and delete the credential variables, just for safety
username = '##############################################'
password = '##############################################'
del username
del password
 
# Look for the SAMLResponse attribute of the input tag (determined by 
# analyzing the debug print lines above)
print(soup.text)
for inputtag in soup.find_all('input'): 
    if(inputtag.get('name') == 'SAMLResponse'): 
        print(inputtag.get('value'))
        assertion = inputtag.get('value')

# Better error handling is required for production use.
if (assertion == ''):
    print(soup.text)
    #TODO: Insert valid error checking/handling
    print('Response did not contain a valid SAML assertion')
    sys.exit(0)

# Debug only
# print(base64.b64decode(assertion))

# Parse the returned assertion and extract the authorized roles 
awsroles = [] 
root = ET.fromstring(base64.b64decode(assertion))
 
for saml2attribute in root.iter('{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'): 
    if (saml2attribute.get('Name') == 'https://aws.amazon.com/SAML/Attributes/Role'): 
        for saml2attributevalue in saml2attribute.iter('{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'):
            awsroles.append(saml2attributevalue.text)
 
# Note the format of the attribute value should be role_arn,principal_arn 
# but lots of blogs list it as principal_arn,role_arn so let's reverse 
# them if needed 
for awsrole in awsroles: 
    chunks = awsrole.split(',') 
    if'saml-provider' in chunks[0]:
        newawsrole = chunks[1] + ',' + chunks[0] 
        index = awsroles.index(awsrole) 
        awsroles.insert(index, newawsrole) 
        awsroles.remove(awsrole)
######################################################################


#################### Get the account names
# destinationUrl="https://signin.aws.amazon.com:443/saml"
# Gets the destination Service provider Url
for inputtag in soup.find_all(re.compile('(FORM|form)')):
    destinationUrl = inputtag.get('action','')
    #Simply populate the parameter with the existing value (picks up hidden fields in the login form)


payload['SAMLResponse'] = assertion

############
# Http call 3

response = session.post(destinationUrl, data=payload, verify=sslverification)
# # Debug the response if needed
# # print (response.text)
# Decode the response and extract the SAML assertion
soup = BeautifulSoup(response.text, features="html.parser")
payload = {}











# # If I have more than one role, ask the user which one they want,
# # otherwise just proceed
# print("")
# if (len(awsroles) > 1 & selectRole):
#     i = 0
#     print("Please choose the role you would like to assume:")
#     for awsrole in awsroles:
#         print('[', i, ']: ', awsrole.split(',')[0])
#         i += 1
#
#     print("Selection: ", end=' ')
#     selectedroleindex = input()
#
#     # Basic sanity check of input
#     if int(selectedroleindex) > (len(awsroles) - 1):
#         print('You selected an invalid role index, please try again')
#         sys.exit(0)
#
#     role_arn = awsroles[int(selectedroleindex)].split(',')[0]
#     principal_arn = awsroles[int(selectedroleindex)].split(',')[1]
#
# else:
#     role_arn = awsroles[0].split(',')[0]
#     principal_arn = awsroles[0].split(',')[1]


# for inputtag in loginsoup.find_all(re.compile('(INPUT|input)')):
#     name = inputtag.get('name','')
#     value = inputtag.get('value','')
#     #Simply populate the parameter with the existing value (picks up hidden fields in the login form)
#     payload[name] = value

# If I have more than one role, ask the user which one they want,
# otherwise just proceed
print("")

role_arns = []
principal_arns = []
awsAccounts = {}
for inputtag in soup.find_all(re.compile('(DIV|div)'), "saml-account-name"):
    name = inputtag.text
    print(name)
    accountId = name[name.index("(")+1:name.index(")")]
    accountName = name[len("Account: "):name.index(" (")]
    awsAccounts[accountId] = accountName



if len(awsroles) > 1 and selectRole:
    print("Please choose the role you would like to assume:")

i = 0
for awsrole in awsroles:
    role_arns.append(awsrole.split(',')[0])
    principal_arns.append(awsrole.split(',')[1])
    if len(awsroles) > 1 and selectRole:
        print('[', i, ']: ', awsrole.split(',')[0])
    i += 1

selectedroleindex = None
if len(awsroles) > 1 and selectRole:
    print("Selection: ", end=' ')
    selectedroleindex = input()

    # Basic sanity check of input
    if int(selectedroleindex) > (len(awsroles) - 1):
        print('You selected an invalid role index, please try again')
        sys.exit(0)




tokens = []
profileNames = []
i = 0
for role_arn in role_arns:
    if selectedroleindex is not None and int(selectedroleindex) == i or selectedroleindex is None:
        accountId = role_arn[len('arn:aws:iam::'):role_arn.index(':role')]
        profileNames.append(role_arn[role_arn.index('role/')+5:]+'@'+awsAccounts[accountId])
        # Use the assertion to get an AWS STS token using Assume Role with SAML
        # conn = boto.sts.connect_to_region(region)
        # tokens.append(conn.assume_role_with_saml(role_arn, principal_arns[i], assertion))


        conn = boto3.client("sts", region_name=region)
        tokens.append(conn.assume_role_with_saml(
            RoleArn=role_arn,
            PrincipalArn=principal_arns[i],
            SAMLAssertion=assertion,
            DurationSeconds=3600
        ))
        i += 1


# Write the AWS STS token into the AWS credential file
home = expanduser("~")
filename = home + awsconfigfile
 
# Read in the existing config file
config = configparser.RawConfigParser()
config.read(filename)
 
# Put the credentials into a saml specific section instead of clobbering
# the default credentials
i=0
for token in tokens:
    if not config.has_section(profileNames[i]):
        config.add_section(profileNames[i])

    config.set(profileNames[i], 'output', outputformat)
    config.set(profileNames[i], 'region', region)
    config.set(profileNames[i], 'aws_access_key_id', token['Credentials']['AccessKeyId'])
    config.set(profileNames[i], 'aws_secret_access_key', token['Credentials']['SecretAccessKey'])
    config.set(profileNames[i], 'aws_session_token', token['Credentials']['SessionToken'])

    # Give the user some basic info as to what has just happened
    print('\n\n----------------------------------------------------------------')
    print('Your new access key pair has been stored in the AWS configuration file {0} under the {1} profile.'.format(filename, profileNames[i]))
    print('Note that it will expire at {0}.'.format(token['Credentials']['Expiration']))
    print('After this time, you may safely rerun this script to refresh your access key pair.')
    print('To use this credential, call the AWS CLI with the --profile option (e.g. aws --profile {0} ec2 describe-instances).'.format(profileNames[i]))
    print('----------------------------------------------------------------\n\n')
    i += 1

# Write the updated config file
with open(filename, 'w+') as configfile:
    config.write(configfile)

# Use the AWS STS token to list all of the S3 buckets
s3 = boto3.client('s3',
     aws_access_key_id=tokens[0]['Credentials']['AccessKeyId'],
     aws_secret_access_key=tokens[0]['Credentials']['SecretAccessKey'],
     aws_session_token=tokens[0]['Credentials']['SessionToken']
)
 
buckets = s3.list_buckets()
 
print('Simple API example listing all S3 buckets:')
print(buckets)
