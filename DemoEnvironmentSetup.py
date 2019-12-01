#!/usr/local/bin/python3

import os, sys. logging
from pprint import pprint
from ipaddress import ip_network
from datetime import datetime
# import Inventory_Modules
import boto3
import argparse
from colorama import init,Fore,Back,Style
from botocore.exceptions import ClientError, NoCredentialsError, EndpointConnectionError

init()

# UsageMsg="You can provide a level to determine whether this script considers only the 'credentials' file, the 'config' file, or both."
parser = argparse.ArgumentParser(
	description="We\'re going to setup the Demo Environment for Amazon Route 53 Resolver",
	prefix_chars='-+/')
parser.add_argument(
	"-p","--profile",
	dest="pProfile",
	metavar="Root profile to use",
	help="You need to specify a profile that represents the ROOT account.")
parser.add_argument(
	"-z","--phz",
	dest="pHostedZone",
	metavar="Domain Name to use for Private Hosted Zone",
	help="Please specify a domain name for your Private Hosted Zone.")
parser.add_argument(
	"-r","--region",
	dest="pRegion",
	metavar="Region for VPCs",
	help="The region we'll create the Demo Environment in.")
parser.add_argument(
	"-a","--accounts",
	dest="pAccounts",
	nargs="*",
	metavar="Accounts within which to make VPCs",
	help="Please provide two additional accounts to use for the VPCs in the demo.")
parser.add_argument(
	'-d', '--debug',
	help="Print lots of debugging statements",
	action="store_const",
	dest="loglevel",
	const=logging.INFO,
	default=logging.CRITICAL)
parser.add_argument(
	'-v', '--verbose',
	help="Be verbose",
	action="store_const",
	dest="loglevel",
	const=logging.WARNING)
args = parser.parse_args()

pProfile=args.pProfile
pAccounts=args.pAccounts
pPHZ=args.pHostedZone
Region=args.pRegion
logging.basicConfig(level=args.loglevel)

##########################
ERASE_LINE = '\x1b[2K'

# Ensure you've enabled resource sharing within the Organization

session_org=boto3.Session(profile_name=pProfile)
client_org=session_org.client('ram')
client_sts=session_org.client('sts')
session_gen=boto3.Session()
client_vpc=session_gen.client('ec2')
# Ensuring that Organization-wide sharing is enabled.
response=client_org.enable_sharing_with_aws_organization()


# Get the account numbers for the 3 accounts (Single Org):
AccountList=['073323372301','906348505515','723919836827']
CIDRList=['10.1.1.0/24','10.2.2.0/24','10.3.3.0/24']
Region='us-east-1'

# Create Credentials for each account
def GetCreds(pAccount):
	try:
		## Shared Services Account
		account_credentials = client_sts.assume_role(
			RoleArn="arn:aws:iam::{}:role/AWSCloudFormationStackSetExecutionRole".format(pAccount),
			RoleSessionName="DemoAcct")['Credentials']
	except ClientError as my_Error:
		if str(my_Error).find("AuthFailure") > 0:
			print("Authorization Failure for account {}".format(pAccount))
	return(account_credentials)

def MakeVPC(pAccount,pRegion,pCIDR):
	creds=GetCreds(pAccount)
	client_vpc=session_gen.client('ec2',
		aws_access_key_id=creds['AccessKeyId'],
		aws_secret_access_key=creds['SecretAccessKey'],
		aws_session_token=creds['SessionToken'],
		region_name=pRegion,
	)
	try:
		vpc=client_vpc.create_vpc(
			CidrBlock=pCIDR,
			AmazonProvidedIpv6CidrBlock=False,
			InstanceTenancy='default'
		)
	except ClientError as my_Error:
		print(my_Error)
		pass

	response = client_vpc.modify_vpc_attribute(
		EnableDnsHostnames={
			'Value': True
		},
		VpcId=vpc['Vpc']['VpcId']
	)

	subnet_cidrs=list(ip_network(pCIDR).subnets(prefixlen_diff=1))
	try:
		subnet1=client_vpc.create_subnet(
			CidrBlock=str(subnet_cidrs[0]),
			VpcId=vpc['Vpc']['VpcId'],
			AvailabilityZone=pRegion+'a'
		)
	except ClientError as my_Error:
		print(my_Error)
		pass
	try:
		subnet2=client_vpc.create_subnet(
			CidrBlock=str(subnet_cidrs[1]),
			VpcId=vpc['Vpc']['VpcId'],
			AvailabilityZone=pRegion+'b'
		)
	except ClientError as my_Error:
		print(my_Error)
		pass
	VPCOutput={'VPCId':vpc['Vpc']['VpcId'],'Subnet1':subnet1['Subnet']['SubnetId'],'Subnet2':subnet2['Subnet']['SubnetId']}
	return(VPCOutput)

def PeerVPCs(pAccount1,pAccount2,pVpcId1,pVpcId2):
	creds1=GetCreds(pAccount1)
	creds2=GetCreds(pAccount2)
	client_vpc=session_gen.client('ec2',
		aws_access_key_id=creds1['AccessKeyId'],
		aws_secret_access_key=creds1['SecretAccessKey'],
		aws_session_token=creds1['SessionToken'],
		region_name=Region,
	)
	peering_req=client_vpc.create_vpc_peering_connection(
		PeerOwnerId=pAccount2,
		PeerVpcId=pVpcId2,
		VpcId=pVpcId1,
	)
	VpcPeeringConnectionId=peering_req['VpcPeeringConnection']['VpcPeeringConnectionId']
	client_vpc=session_gen.client('ec2',
		aws_access_key_id=creds2['AccessKeyId'],
		aws_secret_access_key=creds2['SecretAccessKey'],
		aws_session_token=creds2['SessionToken'],
		region_name=Region,
	)
	accept_peering_req=client_vpc.accept_vpc_peering_connection(
		VpcPeeringConnectionId=VpcPeeringConnectionId
	)
	return(accept_peering_req['VpcPeeringConnection']['VpcPeeringConnectionId'])

def UpdateRouteTables(pAccount,pVpcId,pDestCidr,pPeeringConnectionId):
	creds=GetCreds(pAccount)
	client_vpc=session_gen.client('ec2',
		aws_access_key_id=creds['AccessKeyId'],
		aws_secret_access_key=creds['SecretAccessKey'],
		aws_session_token=creds['SessionToken'],
		region_name=Region,
	)
	# Create new Route Table
	new_rt_table=client_vpc.create_route_table(
		VpcId=pVpcId
	)['RouteTable']['RouteTableId']
	# Add Routes to VPC2 to table in Acct
	add_routes=client_vpc.create_route(
		DestinationCidrBlock=pDestCidr,
		RouteTableId=new_rt_table,
		VpcPeeringConnectionId=pPeeringConnectionId
	)
	# Find asociation-id of main route table in Acct
	main_rt_table=client_vpc.describe_route_tables(
		Filters=[
			{
				'Name': 'association.main',
				'Values': ['true']
			},
			{
				'Name': 'vpc-id',
				'Values': [pVpcId]
			},
		]
	)['RouteTables'][0]['Associations'][0]['RouteTableAssociationId']
	# Associate new Route Table in Acct with the association id of the Main Route Table table for the VPC
	new_main=client_vpc.replace_route_table_association(
		AssociationId=main_rt_table,
		RouteTableId=new_rt_table
	)

def CreatePHZ(pDomainName,pVPCId,pRegion):
	from datetime import datetime
	creds=GetCreds(AccountList[0])
	client_r53=session_gen.client('route53',
		aws_access_key_id=creds['AccessKeyId'],
		aws_secret_access_key=creds['SecretAccessKey'],
		aws_session_token=creds['SessionToken'],
		region_name=pRegion,
	)
	PrivateHZ=client_r53.create_hosted_zone(
		Name=pDomainName,
		VPC={
			'VPCRegion': pRegion,
			'VPCId': pVPCId
		},
		CallerReference='Reference:'+str(datetime.now()),
		HostedZoneConfig={
			'Comment': 'Demo Zone for SRC347',
			'PrivateZone': True
		}
	)
	return(PrivateHZ['HostedZone']['Id'])

def AddRecord(pPHZ,pRecord,pValue):
	creds=GetCreds(AccountList[0])
	client_r53=session_gen.client('route53',
		aws_access_key_id=creds['AccessKeyId'],
		aws_secret_access_key=creds['SecretAccessKey'],
		aws_session_token=creds['SessionToken'],
		region_name=pRegion,
	)
	response = client_r53.change_resource_record_sets(
	HostedZoneId=pPHZ,
	ChangeBatch={
		'Comment': 'Comment String',
		'Changes': [
			{
				'Action': 'UPSERT',
				'ResourceRecordSet': {
					'Name': pRecord,
					'Type': 'A',
					'TTL': 60,
					'ResourceRecords': [
						{
							'Value': pValue
						},
					]
				}
			},
		]
	}
)

def AssociateZoneToVPC(pSharedAccount,pAccount,pPhzId,pVpcId,pRegion):
	if pSharedAccount == pAccount:
		logging.info("The PHZ and the VPC are in the same account. Skipping the association_authorization.")
		SameAccount=True
	else:
		SameAccount=False

	if SameAccount:
		creds=GetCreds(pSharedAccount)
		client_r53=session_gen.client('route53',
			aws_access_key_id=creds['AccessKeyId'],
			aws_secret_access_key=creds['SecretAccessKey'],
			aws_session_token=creds['SessionToken'],
			region_name=pRegion,
		)
		Authorization=client_r53.create_vpc_association_authorization(
			HostedZoneId=pPhzId,
			VPC={
				'VPCRegion': pRegion,
				'VPCId': pVpcId
			}
		)

	creds=GetCreds(pAccount)
	client_r53=session_gen.client('route53',
		aws_access_key_id=creds['AccessKeyId'],
		aws_secret_access_key=creds['SecretAccessKey'],
		aws_session_token=creds['SessionToken'],
		region_name=pRegion,
	)
	response = client_r53.associate_vpc_with_hosted_zone(
		HostedZoneId=pPhzId,
		VPC={
			'VPCRegion': pRegion,
			'VPCId': pVpcId
		}
	)

def CreateEC2(pAccount,pVpcId):
	creds=GetCreds(pAccount)
	client_ec2=session_gen.client('ec2',
		aws_access_key_id=creds['AccessKeyId'],
		aws_secret_access_key=creds['SecretAccessKey'],
		aws_session_token=creds['SessionToken'],
		region_name=pRegion
	)
	client_iam=session_gen.client('iam',
		aws_access_key_id=creds['AccessKeyId'],
		aws_secret_access_key=creds['SecretAccessKey'],
		aws_session_token=creds['SessionToken'],
		region_name=pRegion
	)
	# EC2Profile=client_iam.
	KeyPair=client_ec2.import_key_pair(
		KeyName='DemoPublicKey.OpenSSH.pub',
		PublicKeyMaterial=b'c3NoLXJzYSBBQUFBQjNOemFDMXljMkVBQUFBREFRQUJBQUFCQVFDV0s1ODVROGZHU3BBYlBSTmdnbjA1RjJLT3lhSi9FSEtRdkpGb2xselNYUGEvZlhrQ01HdGVxZmd2eWdObVJoRjUrRmsveTNkS3Q1Q09hR3pRcE1BRDNPOEFrS1pKbkJXWTR4RlVNWTArcjVHaWVZZWZYTjc4NU5oclAyRVI2b3A1N0JveGEvME1XTVVJWHQxclNHWkNuZldVVGk0Q2NibWNxUUN3d05XenBuUUswVjcxRnY4MnhPcWNTQ0JCNFphQWxScXVRY1FZR2ZabzdZeFM5N1YraHFEWGxZOVdCMngrZGRKMUhqVDA4OXBVb0RCY2tRUEFDbWUveXFPNU1xZzZaMzZTUXZqaGJXTHVabDFLQnRqbkY0cStnbi9qdTFtb2s4STV4bW83MlcyRFR6SmszbE5UQ3NBcTljYThHQlBkNng3UUdOVENIVDBlejNpMXhiMEQK'
	)

def CreateSecurityGroup(pAccount,pRegion,pVPCInfo,pSecGrpInfo):
	creds=GetCreds(pAccount)
	client_ec2=session_gen.client('ec2',
		aws_access_key_id=creds['AccessKeyId'],
		aws_secret_access_key=creds['SecretAccessKey'],
		aws_session_token=creds['SessionToken'],
		region_name=pRegion
	)
	SecurityGroupId=client_ec2.create_security_group(
		Description=pSecGrpInfo['Description'],
		GroupName=pSecGrpInfo['GroupName'],
		VpcId=pVPCInfo['VPCId']
	)
	return(SecurityGroupId)

def CreateRoute53Endpoint(pAccount,pRegion,pName,pVPCInfo,pDirection,pSecGrpInfo):
	creds=GetCreds(pAccount)
	client_r53=session_gen.client('route53resolver',
		aws_access_key_id=creds['AccessKeyId'],
		aws_secret_access_key=creds['SecretAccessKey'],
		aws_session_token=creds['SessionToken'],
		region_name=pRegion
	)
	Endpoint=client_53.create_resolver_endpoint(
		CreatorRequestId=pName+':'+str(datetime.now()),
		Name=pName,
		SecurityGroupIds=[pSecGrpInfo['SGId']],
		Direction=pDirection,	#'INBOUND'|'OUTBOUND',
		IpAddresses=[
			{
				'SubnetId': pVPCInfo['Subnet1']
			},
			{
				'SubnetId': pVPCInfo['Subnet2']
			},
		],
		# Tags=[
		#	 {
		# 		'Key': 'string',
		# 		'Value': 'string'
		# 	},
		# ]
	)
	return(Endpoint)

def CreateRoute53Rule(pAccount,pRegion,pRuleName,pRuleType,pDomainName,pTargetIps,pResolverEP):
	creds=GetCreds(pAccount)
	client_r53=session_gen.client('route53resolver',
		aws_access_key_id=creds['AccessKeyId'],
		aws_secret_access_key=creds['SecretAccessKey'],
		aws_session_token=creds['SessionToken'],
		region_name=pRegion
	)
	Route53Rule=client_53.create_resolver_rule(
		CreatorRequestId=pName+":"+str(datetime.now()),
		Name=pName,
		RuleType=pRuleType,		#'FORWARD'|'SYSTEM'|'RECURSIVE' -- Only "FORWARD" is currenrly supported
		DomainName=pDomainName,
		TargetIps=[
			{
				'Ip': pTargetIps[0],
				'Port': 53
			},
			# {
			# 	'Ip': pTargetIps[1],
			# 	'Port': 53
			# },
		],
		ResolverEndpointId=pResolverEP,
		# Tags=[
		# 	{
		# 		'Key': 'string',
		# 		'Value': 'string'
		# 	},
		# ]
	)
	return(Route53Rule)

def CreateRAMShare(pAccount,pRegion,pResourceShareName,pResourceArn,pPrincipals):
	creds=GetCreds(pAccount)
	client_ram=session_gen.client('ram',
		aws_access_key_id=creds['AccessKeyId'],
		aws_secret_access_key=creds['SecretAccessKey'],
		aws_session_token=creds['SessionToken'],
		region_name=pRegion
	)
	RAMShare=client_ram.create_resource_share(
		name=pResourceShareName,
		resourceArns=pResourceArns,	# Expected to be a list
		principals=pPrincipals,		# Expected to be a list
		# tags=[
		# 	{
		# 		'key': 'string',
		# 		'value': 'string'
		# 	},
		# ],
		# allowExternalPrincipals=True|False,
		# clientToken=pResourceShareName+":"+str(datetime.now()),
		# We'll use the default for the below here
		# permissionArns=[
		# 	'string',
		# ]
	)

## Create a VPC in each Account
## Shared Services (Cloud)
# Vpc1=MakeVPC(AccountList[0],Region,CIDRList[0])
## Demo Account 2 (Cloud)
# Vpc2=MakeVPC(AccountList[1],Region,CIDRList[1])
## Demo Account 3 (On-Prem)
# Vpc3=MakeVPC(AccountList[2],Region,CIDRList[2])

## Peering Shared and Demo 1
# PeeringConnection1=PeerVPCs(AccountList[0],AccountList[1],Vpc1['VPCId'],Vpc2['VPCId'])
# Rt_Tables_Update=UpdateRouteTables(AccountList[0],Vpc1['VPCId'],CIDRList[1],PeeringConnection1)
# Rt_Tables_Update=UpdateRouteTables(AccountList[1],Vpc2['VPCId'],CIDRList[0],PeeringConnection1)

## Peering Shared and On-Prem
# PeeringConnection2=PeerVPCs(AccountList[0],AccountList[2],Vpc1['VPCId'],Vpc3['VPCId'])
# Rt_Tables_Update=UpdateRouteTables(AccountList[0],Vpc1['VPCId'],CIDRList[2],PeeringConnection2)
# Rt_Tables_Update=UpdateRouteTables(AccountList[2],Vpc3['VPCId'],CIDRList[0],PeeringConnection2)

## Create a PHZ in the Shared Account
# myPHZ=CreatePHZ('cloud.example.com',Vpc1['VPCId'],Region)
# myRevPHZ=CreatePHZ('1.1.10.in-addr.arpa.',Vpc1['VPCId'],Region)
## Create Test Records within this zone
# NewRecord=AddRecord(myPHZ,'firsttest.cloud.example.com.','10.1.1.1')
# NewRecord=AddRecord(myRevPHZ,'10.1.1.1','firsttest.cloud.example.com.')
## Associate the Private Hosted Zone with Demo Cloud App Account
# ConnectVPCtoPHZ=AssociateZoneToVPC(AccountList[0],AccountList[1],myPHZ,Vpc2['VPCId'],Region)



## Create Route 53 Resolver Inbound / Outbound Endpoints in Shared Services VPC
# OutboundEndpointSecGrpInfo={
# 	'Description':'The Outbound Endpoint for the Shared Services VPC',
# 	'GroupName':'GenericOutboundEndpoint',
# 	'SGId':''
# }
# InboundEndpointSecGrpInfo={
# 	'Description':'The Inbound Endpoint for the Shared Services VPC',
# 	'GroupName':'GenericInboundEndpoint',
# 	'SGId':''
# }
# OutboundEndpointSecGrpInfo['SGId']=CreateSecurityGroup(AccountList[0],Region,Vpc1,OutboundEndpointSecGrpInfo)
# InboundEndpointSecGrpInfo['SGId']=CreateSecurityGroup(AccountList[0],Region,Vpc1,InboundEndpointSecGrpInfo)
# SharedOutboundEP=CreateRoute53Endpoint(AccountList[0],Region,'SharedOutboundEP',Vpc1,'OUTBOUND',OutboundEndpointSecGrpInfo)
# SharedInboundEP=CreateRoute53Endpoint(AccountList[0],Region,'SharedInboundEP',Vpc1,'INBOUND',InboundEndpointSecGrpInfo)

## Create Route53 Resolver Rule for "example.com" (on-Prem)
TargetIps=['10.3.3.38']
# Route53Rule=CreateRoute53Rule(AccountList[0],Region,'ForwardForExampleCom','FORWARD','example.com',TargetIps,SharedOutboundEP['ResolverEndpointId'])

## Need to create the folloing 'SYSTEM' Rules manually, since there isn't automation for them yet
##	amazonaws.com
## 	Whatever name we used for the PHZ
## Share R53 Rules via RAM
ResourceArn='aws:'
# CreateRAMShare(AccountList[0],Region,'ForwardForExampleCom',)
# Associate Rules from RAM to the Demo2 VPC
# Show EC2 can resolve on-prem names after...

'''
TODO:
  Required:
	3 Accounts, each with a VPC in a single region
	  - AppDemo 1
	  - AppDemo2
	  - Shared Services
	CIDR Ranges will be 10.1.1.0/24, 10.2.2.0/24, 10.3.3.0/24
	  - 2 Subnets across 2 Availability zones for each VPC
	  - PHZ owned by the Shared Services Account
	  Shared via RAM - and associated with all three VPCs
	  Shared Services VPC will need inbound/ outbound endpoints
	  Both VPCs will need to be peered with Shared Services VPC, with required routing for the whole CIDR
'''
