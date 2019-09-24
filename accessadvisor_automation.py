#Copyright 2008-2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.

#Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance with the License. A copy of the License is located at
#http://aws.amazon.com/apache2.0/
#or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
#!/usr/bin/env python3


import boto3
import botocore
from botocore.exceptions import ClientError
import time
from datetime import date
import json
import os


'''
Classifying and Enforce Least Privileged Access with access advisor, Permissions Boundary & boto3

Automating audit of least privileged access across AWS IAM entities (users, roles and groups) and applying 
Permissions Boundary to limit access to only services accessed within expiration period. If service is not accessed 
within expiration period it will not be included in the permissions boundary effectively removing access to the service.

Features: 
Tagging IAM entities with access summary data. Total permissions granted, permissions used and % of permissions used.
Tagging with services used be the IAM entity. 

Tag a user and/or role with:
Permissions Coverage - Percentage
Permissions Granted - Total
Permissions Unused - Total

Configurable expiration period. If service is not accessed within the expiration period its, not included in permissions
boundary. Automatically creating and apply permissions boundaries to IAM users and roles based on access advisor data.


access advisor shows the service permissions granted to a role and when permissions were used to access services last. 
You can use this information to revise your policies.
http://docs.aws.amazon.com/console/iam/access-advisor-intro

Access advisor shows the service permissions granted to this role and when those services were last accessed. 
You can use this information to revise your policies.

Note: Recent activity usually appears within 4 hours. Data is stored for a maximum of 365 days, depending when your 
region began supporting this feature.
http://docs.aws.amazon.com/console/iam/access-advisor-regional-tracking-period

This program is created to help AWS Customers achieve least privileged access. Using access advisor APIs it help to
identify IAM Roles that may have unnecessary privileges.  

Limitation: Currently IAM Group resources can not be tagged. Users are tagged instead. 

'''

__version__ = '1.0'
__author__ = '@ddmitriy@'
__email__ = '@ddmitriy@'

'''
DoNotList: list of resource not to tag, this is done to exclude IMA resources that have accessed more then 50 services
DoNotList: list of resource not to apply permissions boundary to.  Currently same variable/list as not to tag.
'''

#  Variables setup via lambda environment variables
bucket = os.environ['DoNotListBucket']
key = os.environ['DoNotListKey']
enforce = os.environ['Enforce']
base_actions = os.environ['BaseActions']

#bucket = 'ddmitriy-anybucket'
#key = 'do_not_list.txt'
#base_actions = 'base_actions.txt'
#enforce = 'yes'

'''
Set days that the permissions/action last accessed will be valid.
If permissions/action have not been used more then defined number days
The permission/action will be removed from permission boundary
'''
#days_expire = 180
days_expire = os.environ['DaysExpire']

#boto3.setup_default_session(profile_name='test1')


NoBoundaryPolicyEdit = [
        "iam:CreatePolicyVersion",
        "iam:DeletePolicy",
        "iam:DeletePolicyVersion",
        "iam:SetDefaultPolicyVersion"
    ]


def get_aws_account_id():
    client = boto3.client("sts")
    accountid = client.get_caller_identity()["Account"]
    return accountid


def get_list_s3(bucket, key):
    print({'msg': 'get_s3_object', 'bucket': bucket, 'key': key})
    s3 = boto3.resource('s3')
    do_not_list = []
    try:
        object = s3.Object(bucket, key)

        '''
        Iterates through all the objects, doing the pagination for you. Each obj is an ObjectSummary, so it doesn't 
        contain the body. You'll need to call get to get the whole body.
        '''
        body = object.get()['Body'].read()
        body = (body.decode('utf8'))
        list = body.split (',')
        for i in list:
            i = i.strip('\n')
            if i:
                do_not_list.append(i)
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == True:
            do_not_list = 'We got an error'
        else:
            do_not_list = "Unexpected error: %s" % e

    return do_not_list

# Get list of IAM users in the AWS account
def get_users():
    client = boto3.client('iam')
    response = None
    user_names = []
    marker = None

    # By default, only 100 roles are returned at a time.
    # 'Marker' is used for pagination.
    while (response is None or response['IsTruncated']):
        # Marker is only accepted if result was truncated.
        if marker is None:
            response = client.list_users()
        else:
            response = client.list_users(Marker=marker)

        users = response['Users']
        for user in users:
            user_names.append(user['Arn'])

        if response['IsTruncated']:
            marker = response['Marker']

    return user_names

# Get list of IAM roles in the aws account
def get_roles():
    # Create a client that will be referenced to make an API call
    client = boto3.client('iam')
    response = None
    role_names = []
    marker = None

    # By default, only 100 roles are returned at a time.
    # 'Marker' is used for pagination.
    while (response is None or response['IsTruncated']):
        # Marker is only accepted if result was truncated.
        if marker is None:
            response = client.list_roles()
        else:
            response = client.list_roles(Marker=marker)
        roles = response['Roles']
        for role in roles:
            role_names.append(role['Arn'])

        if response['IsTruncated']:
            marker = response['Marker']

    return role_names

# Get list of IAM groups in the AWS account
def get_groups():
    client = boto3.client('iam')
    response = None
    group_names = []
    marker = None

    # By default, only 100 roles are returned at a time.
    # 'Marker' is used for pagination.
    while (response is None or response['IsTruncated']):
        # Marker is only accepted if result was truncated.
        if marker is None:
            response = client.list_groups()
        else:
            response = client.list_groups(Marker=marker)

        groups = response['Groups']
        for group in groups:
            group_names.append(group['Arn'])

        if response['IsTruncated']:
            marker = response['Marker']

    return group_names

# Create a report for each role
def generateServiceLastAccessedDetails(arn):
    client = boto3.client('iam')
    response = client.generate_service_last_accessed_details(
        Arn=arn
    )
    jobid = response['JobId']
    return jobid

# Using jobid obtain permission used and not used information
def getServiceLastAccessedDetails(jobid):
    # if you have thousands of roles lambda may time out
    response = None
    marker = None
    client = boto3.client('iam')

    # By default, only 100 roles are returned at a time.
    # 'Marker' is used for pagination.
    status = False
    while (response is None or response['IsTruncated']):
        # Marker is only accepted if result was truncated.
        while status != "COMPLETED":
            try:
                if marker is None:
                    response = client.get_service_last_accessed_details(
                        JobId=jobid
                    )
                else:
                    response = client.get_service_last_accessed_details(
                        JobId=jobid,
                        Marker=marker
                    )

                status = response['JobStatus']
                print('job status: ', status)
                time.sleep(2)
            except botocore.exceptions.ClientError as e:
                status = False
                if e.response['Error']['Code'] == True:
                    response = 'We got an error'
                else:
                    response = "Unexpected error: %s" % e
    return response

# Using jobid obtain permission used and not used information with entities
def getServiceLastAccessedDetailswithEntities(jobid, service):
    # if you have thousands of roles lambda may time out
    response = None
    marker = None
    client = boto3.client('iam')

    # By default, only 100 roles are returned at a time.
    # 'Marker' is used for pagination.
    status = False
    while (response is None or response['IsTruncated']):
        # Marker is only accepted if result was truncated.
        while status != "COMPLETED":
            try:
                if marker is None:
                    response = client.get_service_last_accessed_details_with_entities(
                        JobId=jobid,
                        ServiceNamespace=service
                    )
                else:
                    response = client.get_service_last_accessed_details_with_entities(
                        JobId=jobid,
                        ServiceNamespace=service,
                        Marker=marker
                    )

                status = response['JobStatus']
                print('job status: ', status)
                time.sleep(2)
            except botocore.exceptions.ClientError as e:
                status = False
                if e.response['Error']['Code'] == True:
                    response = 'We got an error'
                else:
                    response = "Unexpected error: %s" % e
    return response


#########################################
# WORK IN PROGRESS SECTION
#########################################

#
def list_attached_role_policies(role, path):
    client = boto3.client('iam')
    try:
        response = client.list_attached_role_policies(
            RoleName=role,
            PathPrefix=path
        )
        policies = response
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == True:
            policies = 'We got an error'
        else:
            policies = "Unexpected error: %s" % e
    return policies

def list_attached_user_policies(user, path):
    client = boto3.client('iam')
    try:
        response = client.list_attached_user_policies(
            UserName=role,
            PathPrefix=path
        )
        policies = response
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == True:
            policies = 'We got an error'
        else:
            policies = "Unexpected error: %s" % e
    return policies


def list_attached_group_policies(role, path):
    client = boto3.client('iam')
    try:
        response = client.list_attached_group_policies(
            GroupName=role,
            PathPrefix=path
        )
        policies = response
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == True:
            if e.response['Error']['Code'] == True:
                policies = 'We got an error'
            else:
                policies = "Unexpected error: %s" % e
    return policies


def list_granting_policies(arn, services):

    response = None
    marker = None
    client = boto3.client('iam')

    # By default, only 100 roles are returned at a time.
    # 'Marker' is used for pagination.
    status = False
    while (response is None or response['IsTruncated']):
        # Marker is only accepted if result was truncated.
        while status != "COMPLETED":
            try:
                if marker is None:
                    response = client.list_policies_granting_service_access(
                        Arn=arn,
                        ServiceNamespaces=services
                    )
                else:
                    response = client.list_policies_granting_service_access(
                        Marker=marker,
                        Arn=arn,
                        ServiceNamespaces=services
                    )

                status = response['JobStatus']
                print('job status: ', status)
                time.sleep(2)
            except botocore.exceptions.ClientError as e:
                status = False
                if e.response['Error']['Code'] == True:
                    response = 'We got an error'
                else:
                    response = "Unexpected error: %s" % e

    return response


########################################
########################################

# Tag the role with key and value
def tag_role(role, key, value):
    client = boto3.client('iam')
    try:
        response = client.tag_role(
            RoleName=role,
            Tags=[
                {
                    'Key': key,
                    'Value': value
                },
            ]
        )
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == True:
            response = 'We got an error'
        else:
            response = "Unexpected error: %s" % e
    return response

# Tag the user with key and value
def tag_user(user, key, value):
    client = boto3.client('iam')
    try:
        response = client.tag_user(
            UserName=user,
            Tags=[
                {
                    'Key': key,
                    'Value': value
                },
            ]
        )
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == True:
            response = 'We got an error'
        else:
            response = "Unexpected error: %s" % e
    return response


###########################################
# Review of IAM users with access advisor
###########################################
def iam_users():
    do_not_list = get_list_s3(bucket, key)
    users_list = get_users()
    for user in users_list:
        print({'start': user})
        services = []
        # Let's declare counting variables for each user
        used_count = 0
        unused_count = 0
        total_count = 0

        # Make APIs calls to get access advisor data for a user
        jobid = (generateServiceLastAccessedDetails(user))
        details = (getServiceLastAccessedDetails(jobid))

        # Since we get user ARN we can use syntax below to just get the name
        username = user.split("/")[-1]

        # Let's loop trough all the services
        for service in details['ServicesLastAccessed']:

            total_count += 1 # Start counting the services

            # Determine if service has been access by the user
            if service['TotalAuthenticatedEntities'] > 0 and service['LastAuthenticated']:

                # Get data when user last authenticated to the services
                LastAuthenticated = (service['LastAuthenticated'])
                dategap = (date.today() - LastAuthenticated.date())  # Getting data

                used_count += 1  # Now if services is accessed +1
                if int(dategap.days) > int(days_expire):  # If accessed outside of expiration period
                    used_count -= 1     # Now -1 if has been accessed outside expiration period
                    print('---> used count', used_count)

                    # Getting data to print correctly
                    dategap = str(dategap)
                    dategap = dategap.split(",")[0]

                    # Print detail message
                    print(logger_detail('detail', 'user', username, service['ServiceNamespace'],
                                        service['LastAuthenticated'],
                                        service['TotalAuthenticatedEntities'],
                                        ('Accessed outside allowed period,', str(dategap),
                                         'ago, CONSIDER REMOVING THIS PRIVILEGE')))
                else:

                    # Accessed within the expriation period we will tag user
                    # We'll make a call to another access advisor API to get details for each services accessed
                    details_w_entity = (getServiceLastAccessedDetailswithEntities(jobid, service['ServiceNamespace']))
                    entityinfo = (details_w_entity['EntityDetailsList'])
                    for e in entityinfo:
                        user = e['EntityInfo']['Name']

                        '''
                        This will tag user with each service it had accessed.  This does not work well for admin users.
                        Admin users access a lot of services and will easily hit 50 tag limit on a user entity.
                        Rather then tagging we will just add this to the log
                        '''

                        # Exclude from tagging if in the do_not_list
                        if user in do_not_list:
                            print(logger_detail('detail', 'user', user, service['ServiceNamespace'],
                                                service['LastAuthenticated'],
                                                service['TotalAuthenticatedEntities'],
                                                'entity is in the do not tag list, ' +
                                                'entity will not be tagged with services'))

                            # Next build the list of services accessed by a user
                            services.append(service['ServiceNamespace'])
                        else:
                            # Tag user with key = 'userServiceAccessed & value = 'ServiceNamespace'
                            tag_user(user, 'userServiceAccessed' + str(used_count), service['ServiceNamespace'])
                            print(logger_detail('detail', 'user', user, service['ServiceNamespace'],
                                                service['LastAuthenticated'],
                                                service['TotalAuthenticatedEntities'],
                                                'tagged user'))

                            # Next build the list of services accessed by a user
                            services.append(service['ServiceNamespace'])
            else:
                # Add service to unused count
                unused_count += 1
                if service['TotalAuthenticatedEntities'] == 0:
                    print({'unsued count': unused_count})
                    username = user.split("/")[-1]  # get name of the user from arn

                    # print detail
                    print(logger_detail('detail', 'user', username, service['ServiceNamespace'],
                                        'n/a',
                                        service['TotalAuthenticatedEntities'],
                                        'CONSIDER REMOVING THIS PRIVILEGE'))

        # Here we will build and apply Permissions Boundary
        if enforce == 'yes': # Check if enforce flag is set to "yes"
            if user in do_not_list: # Check if user in the do_not_list
                print({'msg': 'skipping_user', 'user': username, 'reason': 'do_not_list'})
            else:
                if services:  # checking if services (action) is populated to create a permissions boundary

                    # Creating and adding permission boundary
                    # Call module to create an IAM policy with services, returns IAM policy arn
                    policy_ARN = create_iam_policy(username, services, get_aws_account_id())
                    # Using IAM policy ARN attach the permissions boundary to the user
                    attach_user_pb(username, policy_arn)

                else:
                    # creating a base permission boundary for users that didn't access any service, services is empty
                    services = get_list_s3(bucket, base_actions)  # if changed, update the policy creation module
                    print({'msg': 'get_s3_object', 'object': services, 'user': username})
                    # Creating and adding permission boundary
                    policy_ARN = create_iam_policy(username, services, get_aws_account_id())
                    attach_user_pb(username, policy_arn)

        #  Calculating the total services with permissions for a given user
        #  total_count = used_count + unused_count
        #  Calculation coverage percentage of users used compared to services allowed
        if total_count == 0:
            print("user has no permissions")
            calc_coverage = 'n/a'
            total_count = 'n/a'
            unused_count = 'n/a'
            print(logger_summary('summary', 'user', user, None, None, None))
        else:
            calc_coverage = round(used_count/total_count * 100)
        # Adding a tag to a user with % | the higher the number the better
        tag_user(username, 'Permissions_Coverage_Percent', (str(calc_coverage)))
        tag_user(username, 'Permissions_Granted', str(total_count))
        tag_user(username, 'Permissions_Unused', str(unused_count))
        print(logger_summary('summary', 'user', username, str(total_count), str(unused_count), str(calc_coverage)))


###########################################
# Review of IAM roles with access advisor
###########################################
def iam_roles():
    do_not_list = get_list_s3(bucket, key)
    roles_list = get_roles()
    for role in roles_list:
        print({'start': role})
        services = []
        # Let's declare counting variables for each role
        used_count = 0
        unused_count = 0
        total_count = 0

        # Make APIs calls to get access advisor data for a role
        jobid = (generateServiceLastAccessedDetails(role))
        details = (getServiceLastAccessedDetails(jobid))

        # Since we get role ARN we can use syntax below to just get the name
        rolename = role.split("/")[-1]

        # Let's loop trough all the services
        for service in details['ServicesLastAccessed']:

            total_count += 1 # Start counting the services

            # Determine if service has been access by the role
            if service['TotalAuthenticatedEntities'] > 0 and service['LastAuthenticated']:

                # Get data when role last authenticated to the services
                LastAuthenticated = (service['LastAuthenticated'])
                dategap = (date.today() - LastAuthenticated.date())  # Getting data

                used_count += 1  # Now if services is accessed +1
                if int(dategap.days) > int(days_expire):  # If accessed outside of expiration period
                    used_count -= 1     # Now -1 if has been accessed outside expiration period
                    print('---> used count', used_count)

                    # Getting data to print correctly
                    dategap = str(dategap)
                    dategap = dategap.split(",")[0]

                    # Print detail message
                    print(logger_detail('detail', 'role', rolename, service['ServiceNamespace'],
                                        service['LastAuthenticated'],
                                        service['TotalAuthenticatedEntities'],
                                        ('Accessed outside allowed period,', str(dategap),
                                         'ago, CONSIDER REMOVING THIS PRIVILEGE')))
                else:

                    # Accessed within the expriation period we will tag role
                    # We'll make a call to another access advisor API to get details for each services accessed
                    details_w_entity = (getServiceLastAccessedDetailswithEntities(jobid, service['ServiceNamespace']))
                    entityinfo = (details_w_entity['EntityDetailsList'])
                    for e in entityinfo:
                        role = e['EntityInfo']['Name']
                        # This will tag role with each service it had accessed.  This does not work well for admin roles.
                        # Admin roles access a lot of services and will easily hit 50 tag limit on a role entity.
                        # Rather then tagging we will just add this to the log,

                        # Exclude from tagging if in the do_not_list
                        if role in do_not_list:
                            print(logger_detail('detail', 'role', role, service['ServiceNamespace'],
                                                service['LastAuthenticated'],
                                                service['TotalAuthenticatedEntities'],
                                                'entity is in the do not tag list, ' +
                                                'entity will not be tagged with services'))

                            # Next build the list of services accessed by a role
                            services.append(service['ServiceNamespace'])
                        else:
                            # Tag role with key = 'roleServiceAccessed & value = 'ServiceNamespace'
                            tag_role(role, 'roleServiceAccessed' + str(used_count), service['ServiceNamespace'])
                            print(logger_detail('detail', 'role', role, service['ServiceNamespace'],
                                                service['LastAuthenticated'],
                                                service['TotalAuthenticatedEntities'],
                                                'tagged role'))

                            # Next build the list of services accessed by a role
                            services.append(service['ServiceNamespace'])
            else:
                # Add service to unused count
                unused_count += 1
                if service['TotalAuthenticatedEntities'] == 0:
                    print({'unsued count': unused_count})
                    rolename = role.split("/")[-1]  # get name of the role from arn

                    # print detail
                    print(logger_detail('detail', 'role', rolename, service['ServiceNamespace'],
                                        'n/a',
                                        service['TotalAuthenticatedEntities'],
                                        'CONSIDER REMOVING THIS PRIVILEGE'))


        # Here we will build and apply Permissions Boundary
        if enforce == 'yes': # Check if enforce switch is set to "yes"
            if role in do_not_list: # Check if role in the do_not_list
                print({'msg': 'skipping_role', 'user': rolename, 'reason': 'do_not_list'})
            else:
                if services:  # checking if services (action) is populated to create a permissions boundary

                    # Creating and adding permission boundary
                    # Call module to create an IAM policy with services, returns IAM policy arn
                    policy_ARN = create_iam_policy(rolename, services, get_aws_account_id())
                    # Using IAM policy ARN attach the permissions boundary to the role
                    attach_role_pb(rolename, policy_arn)

                else:
                    # creating a base permission boundary for users that didn't access any service, services is empty
                    services = get_list_s3(bucket, base_actions)  # if changed, update the policy creation module
                    print({'msg': 'get_s3_object', 'object': services, 'role': rolename})
                    # Creating and adding permission boundary
                    policy_ARN = create_iam_policy(rolename, services, get_aws_account_id())
                    attach_role_pb(rolename, policy_arn)

        #  Calculating the total services with permissions for a given role
        #  total_count = used_count + unused_count
        #  Calculation coverage percentage of roles used compared to services allowed
        if total_count == 0:
            print("Role has no permissions")
            calc_coverage = 'n/a'
            total_count = 'n/a'
            unused_count = 'n/a'
            print(logger_summary('summary', 'role', role, None, None, None))
        else:
            calc_coverage = round(used_count/total_count * 100)
        # Adding a tag to a role with % | the higher the number the better
        tag_role(rolename, 'Permissions_Coverage_Percent', (str(calc_coverage)))
        tag_role(rolename, 'Permissions_Granted', str(total_count))
        tag_role(rolename, 'Permissions_Unused', str(unused_count))
        print(logger_summary('summary', 'role', rolename, str(total_count), str(unused_count), str(calc_coverage)))

###########################################
# Review of IAM Groups with access advisor
###########################################
def iam_groups():
    do_not_list = get_list_s3(bucket, key)
    groups_list = get_groups()
    for group in groups_list:
        used_count = 0
        unused_count = 0

        # Printing some data to standard output, if ran as lambda output can be reviewed in cloudwatch logs
        jobid = (generateServiceLastAccessedDetails(group))
        details = (getServiceLastAccessedDetails(jobid))
        for service in details['ServicesLastAccessed']:
            if service['TotalAuthenticatedEntities'] > 0:
                used_count += 1
                # Getting entity accessed details
                details_w_entity = (getServiceLastAccessedDetailswithEntities(jobid, service['ServiceNamespace']))
                entityinfo = (details_w_entity['EntityDetailsList'])
                for e in entityinfo:
                    user = e['EntityInfo']['Name']
                    # This will tag user with each service it had accessed.  This does not work well for admin users.
                    # Admin users access a lot of services and will easily hit 50 tag limit on a user entity.
                    # Rather than tagging we will just add this to the log

                    if user in do_not_list:
                        print(logger_detail('detail', 'group', user, service['ServiceNamespace'],
                                            service['TotalAuthenticatedEntities'],
                                            service['LastAuthenticated'],
                                            'entity is in the do not tag list, entity will not be tagged with services'))

                    else:
                        tag_user(user, 'GroupServiceAccessed' + str(used_count), service['ServiceNamespace'])
                        print(logger_detail('detail', 'group', user, service['ServiceNamespace'],
                                            service['LastAuthenticated'],
                                            service['TotalAuthenticatedEntities'],
                                            'tagged user, via group permission'))

        for service in details['ServicesLastAccessed']:
            if service['TotalAuthenticatedEntities'] == 0:
                unused_count +=1
        # Calculating the total services with permissions for a given role
        total_count = used_count + unused_count
        # Calculation coverage percentage of roles used compared to services allowed
        if total_count == 0:
            print(logger_summary('summary', 'group', group, 'n/a', 'n/a', 'n/a'))
            calc_coverage = 'n/a'
            total_count = 'n/a'
            unused_count = 'n/a'
        else:
            calc_coverage = round(used_count/total_count * 100)
        print(logger_summary('summary', 'group', group, str(total_count), str(unused_count), str(calc_coverage)))


##########################################################################
# Services list will be passed from user / role access advisor review list
# Services will be used as Action in the IAM policy to define permissions boundary
def create_iam_policy(iam_entity, servicelist, accountid):

    servicelist2 = []  # We'll use this variable to store modified list of services to use in IAM policy json
    # Let's define iam policy name we'll use
    iam_policy_name = 'AccessAdvisor-PB-' + iam_entity

    # Let's define Permissions Boundary policy Arn
    policyARN = 'arn:aws:iam::' + accountid + ':policy/AccessAdvisor-PB-' + iam_entity

    # Check if this is a base permissions boundary for user/role
    # That didn't access any services during expiration period
    if servicelist == get_list_s3(bucket, base_actions):
        print({'msg': 'create_base_actions_permissions_boundary', 'policy_arn': policyarn})
        servicelist2 = servicelist

    # In this section we're adding :*  to Action so that we can use it in IAM policy json
    else:
        for s in servicelist:
            s = s + ':*'
            servicelist2.append(s)
        servicelist2.sort()

    # Now we're ready to check on existing IAM policy
    client = boto3.client('iam')
    print('CHECK IF POLICY EXISTS')
    try:
        # Here we're calling API to get policy
        # AWS versions IAM policies and we can store maximum of 5 policy versions
        response = client.get_policy(PolicyArn = policyarn)
        print('Policy: ', response['Policy']['Arn'])
        ARN = (response['Policy']['Arn'])
        # Below we're getting version of the policy
        policyver = (response['Policy']['DefaultVersionId'])
        # Here we're making another API call to get the current version of the policy
        # This is where we'll get the actual json of the IAM policy
        response_policy_ver = client.get_policy_version(
            PolicyArn=arn,
            VersionId=policyver
        )
        # Next we get the "Action" that is included in the policy, for the first statement in json
        version_action = (response_policy_ver['PolicyVersion']['Document']['Statement'][0]["Action"])
        if isinstance(servicelist2, list):
            servicelist2.sort()

        # Now we'll validate that the "Action" in the policy matches what access advisor identified as used Actions
        # If this policy attached does not match we will update the policy
        if version_action == servicelist2:
            print({"msgtype": 'policy validation',
                   "entitytype": 'policy',
                   "entityname": iam_policy_name,
                   'msg': 'policy matches'})

        # If policy did NOT match, we'll build a policy
        else:
            print({"msgtype": 'policy validation',
                   "entitytype": 'policy',
                   "entityname": iam_policy_name,
                   'msg': 'IAM services changed, need new policy'})

            # Here we'll build policy json, passing servicelist2 list of actions from access advisor and restrict
            # with "Effect": "Deny: No Boundary policy Edit and No Boundary Role & User Delete
            policy = {'Version': '2012-10-17'}
            policy['Statement'] = [{
                "Sid": "",
                "Effect": "Allow",
                "Action": [],
                "Resource": "RESOURCE_ARN"},
                {
                    "Sid": "",
                    "Effect": "Deny",
                    "Action": [],
                    "Resource": "RESOURCE_ARN"},
                {
                    "Sid": "",
                    "Effect": "Deny",
                    "Action": [],
                    "Resource": "RESOURCE_ARN"}
            ]
            policy['Statement'][0]['Sid'] = 'AccessAdvisorPermissionsBoundary'
            policy['Statement'][0]['Action'] = servicelist2
            policy['Statement'][0]['Resource'] = '*'
            policy['Statement'][1]['Sid'] = 'NoBoundaryPolicyEdit'
            policy['Statement'][1]['Action'] = NoBoundaryPolicyEdit
            policy['Statement'][1]['Resource'] = 'arn:aws:iam::' + accountid + ':policy/' + iam_policy_name
            policy['Statement'][2]['Sid'] = 'NoBoundaryRoleDelete'
            policy['Statement'][2]['Action'] = [
                                                "iam:DeleteRolePermissionsBoundary",
                                                "iam:DeleteUserPermissionsBoundary"
                                                ]
            policy['Statement'][2]['Resource'] = '*'
            iam_policy_json = json.dumps(policy, indent=2)

            print({'IAM POLICY': iam_policy_name})
            print({'IAM POLICY JSON': iam_policy_json})
            print({'Policy Arn': arn})

            #  Now we are going to create an IAM policy, if policy with the same name already exists we'll get and error
            try:
                response = client.create_policy(
                    PolicyName=iam_policy_name,
                    PolicyDocument=iam_policy_json,
                )
                print({"msgtype": 'API RESPONSE',
                       "entitytype": 'policy',
                       "entityname": iam_policy_name,
                       'arn': response['Policy']['Arn']})

            # if we got and error create a policy, next we'll try to create a new policy version to update policy
            except ClientError as e:
                print({"msgtype": 'error',
                       "entitytype": 'policy',
                       "entityname": iam_policy_name,
                       "msg": e})

                # Create policy verson, using policy json we created above
                try:
                    response = client.create_policy_version(
                        PolicyArn=arn,
                        PolicyDocument=iam_policy_json,
                        SetAsDefault=True
                    )
                    print({"msgtype": 'created',
                           "entitytype": 'policy',
                           "entityname": iam_policy_name,
                           "msg": 'POLICY VERSION WAS SUCCESSFULLY CREATED'})

                # AWS allows storage for 5 policy versions, if we we're successful crate a policy version
                # We'll need to delete an older version
                except ClientError as e:
                    print({"msgtype": 'error',
                           "entitytype": 'policy',
                           "entityname": iam_policy_name,
                           "msg": 'Couldn\'t create policy version'})

                    print({'Policy Version': policyver[1:]})
                    p_id = policyver[1:]
                    p_id = (int(
                        p_id) - 3)  # Setting version ID to be used to deleted a previous version of the iam policy
                    print({"msgtype": 'attempt',
                           "entitytype": 'policy',
                           "entityname": iam_policy_name,
                           "msg": 'Trying to remove policy version'})

                    # Deleting policy version
                    response = client.delete_policy_version(
                        PolicyArn=arn,
                        VersionId='v' + str(p_id)
                    )
                    # Now we should be able to crate a new policy version
                    response = client.create_policy_version(
                        PolicyArn=arn,
                        PolicyDocument=iam_policy_json,
                        SetAsDefault=True
                    )

                    print({"msgtype": 'removed',
                           "entitytype": 'policy',
                           "entityname": iam_policy_name,
                           "msg": 'Successfully removed policy version' + str(p_id)})

                    print({"msgtype": 'created',
                           "entitytype": 'policy',
                           "entityname": iam_policy_name,
                           "msg": 'NEW POLICY VERSION WAS SUCCESSFULLY CREATED'})

    # If we we're able to get policy, then it doesn't exist and we need to create one
    # We'll build policy json and build the IAM policy
    except ClientError as e:

        print({"msgtype": 'create policy',
               "entitytype": 'policy',
               "entityname": iam_policy_name,
               "msg": 'STARTING POLICY CREATION'})
        policy = {'Version': '2012-10-17'}
        policy['Statement'] = [{
            "Sid": "",
            "Effect": "Allow",
            "Action": [],
            "Resource": "RESOURCE_ARN"},
            {
            "Sid": "",
            "Effect": "Deny",
            "Action": [],
            "Resource": "RESOURCE_ARN"},
            {
            "Sid": "",
            "Effect": "Deny",
            "Action": [],
            "Resource": "RESOURCE_ARN"}
        ]
        policy['Statement'][0]['Sid'] = 'AccessAdvisorPermissionsBoundary'
        policy['Statement'][0]['Action'] = servicelist2
        policy['Statement'][0]['Resource'] = '*'
        policy['Statement'][1]['Sid'] = 'NoBoundaryPolicyEdit'
        policy['Statement'][1]['Action'] = NoBoundaryPolicyEdit
        policy['Statement'][1]['Resource'] = 'arn:aws:iam::' + accountid + ':policy/' + iam_policy_name
        policy['Statement'][2]['Sid'] = 'NoBoundaryRoleDelete'
        policy['Statement'][2]['Action'] = [
                                            "iam:DeleteRolePermissionsBoundary",
                                            "iam:DeleteUserPermissionsBoundary"
                                            ]
        policy['Statement'][2]['Resource'] = '*'
        iam_policy_json = json.dumps(policy, indent=2)

        print({'IAM POLICY': iam_policy_name})
        print({'IAM POLICY JSON': iam_policy_json})
        try:
            response = client.create_policy(
                PolicyName=iam_policy_name,
                PolicyDocument=iam_policy_json,
            )
            print({"msgtype": 'created',
                   "entitytype": 'policy',
                   "entityname": iam_policy_name,
                   "msg": 'POLICY VERSION WAS SUCCESSFULLY CREATED'})
            print('Policy Created: ', response['Policy']['Arn'])
        except ClientError as e:
            print('error creating policy')
            print(e)
    return policyarn


# Attach permissions boundary
def attach_user_pb(user, pb):
    do_not_list = get_list_s3(bucket, key)
    client = boto3.client('iam')
    iam = boto3.resource('iam')
    if user in do_not_list: # Exception for users in do not tag list to be assigned a permission boundary
        print(logger_detail('detail', 'user', user, 'n/a', 'n/a', 'n/a', 'skipping adding role to permissions boundary'))
    else:
        try:
            response = client.put_user_permissions_boundary(
                UserName=user,
                PermissionsBoundary=pb
            )
            output = response
        except ClientError as e:
            output = logger_detail('error', 'user', user, 'n/a', 'n/a', 'n/a', 'adding permissions boundary')
            print(e)

        return output

def attach_role_pb(role, pb):
    do_not_list = get_list_s3(bucket, key)
    client = boto3.client('iam')
    iam = boto3.resource('iam')
    if role in do_not_list: # Exception for roles in do not tag list to be assigned a permission boundary
        print(logger_detail('detail', 'role', role, 'n/a', 'n/a', 'n/a', 'skipping adding role to permissions boundary'))
    else:
        try:
            response = client.put_role_permissions_boundary(
                RoleName=role,
                PermissionsBoundary=pb
            )
            output = response
        except ClientError as e:
            output = logger_detail('error', 'user', role, 'n/a', 'n/a', 'n/a', 'adding permissions boundary')

        return output

# Defining standard logging module
#
# Possible log messages
# msgtype - detail; summary
# entitytype - user, role, group
# entityname - name of the entity
# service - name of the services
# TotalAuthenticatedEntities = number of authenticated entities for the service
# message - any custom messages

def logger_detail(msgtype, entitytype, entityname, service, LastAuthenticated, totalauthenticatedentities, message):
    log = {}
    log = {"msgtype": msgtype, "entitytype": entitytype, "entityname": entityname, "service": service, 'LastAuthenticated': LastAuthenticated, "totalauthenticatedentities": totalauthenticatedentities, "message": message}
    return log

def logger_summary(msgtype, entitytype, entityname, permissionsgranted, permissionsused, permissionscoverage):
    log = {}
    log = {"msgtype": msgtype, "entitytype": entitytype, "entityname": entityname, "permissionsgranted": permissionsgranted, "permissionsNOTused": permissionsused, "permissionscoverage": permissionscoverage}
    return log

# main program
# Printing some data to standard output, if ran as lambda output can be reviewed in cloudwatch logs
# This will also generate audit trail that this "audit" script has ran
def lambda_handler(event, context):

    print({'msg': 'start_execution', 'program': 'access_advisor_automation', 'enforcement': enforce,
           'expiration': days_expire, 'bucket': bucket, 'key': key})

    iam_users()
    iam_roles()
    iam_groups()

    print({'msg': 'end_execution', 'program': 'access_advisor_automation', 'enforcement': enforce,
           'expiration': days_expire, 'bucket': bucket, 'key': key})


if __name__ == '__main__':
    lambda_handler(None, None)