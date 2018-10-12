# This demonstration will find S3 buckets that are public under a few conditions you can interpret below.
# It includes code to remediate discovered issues, but this code is not activated yet.
# To complete the lab, alter the code to either send you an alert or automatically remediat ethe issue... or both.
# Note: some code used by permission of DisruptOPS

import json
import boto3
from botocore.exceptions import ClientError

def assess(event, context):

    s3_client = boto3.client('s3')
    s3_resource = boto3.resource('s3')

    public_acl_indicator = 'http://acs.amazonaws.com/groups/global/AllUsers'
    permissions_to_check = ['READ', 'WRITE']
    public_buckets = {}

    #Determine if the bucket ACL provides public access
    try:
        list_bucket_response = s3_client.list_buckets()

        for bucket_list in list_bucket_response['Buckets']:
            bucket_acl_response = s3_client.get_bucket_acl(Bucket=bucket_list['Name'])

            for grant in bucket_acl_response['Grants']:
                for (k, v) in grant.items():
                    if k == 'Permission' and any(permission in v for permission in permissions_to_check):
                        for (grantee_attrib_k, grantee_attrib_v) in grant['Grantee'].items():
                            if 'URI' in grantee_attrib_k and grant['Grantee']['URI'] == public_acl_indicator:
                                if public_buckets == {}:
                                    public_buckets['Public'] = [bucket_list['Name']]
                                else:
                                    public_buckets['Public'] += [bucket_list['Name']]
    except ClientError as e:
        print(e.response)


    #Determine if a resource policy provides public access
    for bucket in s3_resource.buckets.all():
        try:
            bucket_policy = s3_client.get_bucket_policy(
                Bucket=bucket.name
                )
            assert isinstance(bucket_policy, object)
            policy_statement = json.loads(bucket_policy['Policy'])

            for (k, v) in policy_statement.items():
                if k == "Principal" and "*" in v:
                    public_buckets[v] += bucket.name
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                pass
            else:
                print(e.response)
    return public_buckets
def policy_fixer(bucket_name):
    try:
        s3 = session.client('s3')
        bucket_policy = s3.get_bucket_policy(
            Bucket=bucket_name
        )
        assert isinstance(bucket_policy, object)
        policy = json.loads(bucket_policy['Policy'])
        restriction = {
            "IpAddress": {
                "aws:SourceIp": iplist}}
        new_statement = []
        for statement in policy['Statement']:
            if statement['Principal'] == {"AWS":"*"} or statement['Principal'] == '*':
                if 'Condition' in statement:
                    if 'IpAddress' in statement['Condition']:
                        if 'aws:SourceIp' in statement['Condition']['IpAddress']:
                            if '0.0.0.0/0' in statement['Condition']['IpAddress']['aws:SourceIp']:
                                statement['Condition']['IpAddress']['aws:SourceIp'].remove('0.0.0.0/0')
                                statement['Condition']['IpAddress']['aws:SourceIp'] += iplist
                    else:
                        statement['Condition']['IpAddress'] = {'aws:SourceIp': iplist}
                else:
                    statement['Condition'] = restriction
            new_statement.append(statement)
        new_policy = {'Version': policy['Version'], 'Statement': new_statement}
        if 'Id' in policy:
            new_policy['Id'] = policy['Id']
        print(json.dumps(new_policy))
        update_policy = s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(new_policy))
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
            pass
        elif e.response['Error']['Code'] == 'ServiceFailure:':
            t.q_status_send(detail=e, status=c.ERROR)
            log.debug('Error checking entity - service unavailable.')
            return t.error(e)
        else:
            print(e.response)

def add_basic_bucket_policy(bucket_name):
    try:
        s3 = session.client('s3')
        try:
            bucket_policy = s3.get_bucket_policy(
                Bucket=bucket_name
            )
        except ClientError as e:
            if 'NoSuchBucketPolicy' in str(e):
                new_policy = {
                    "Version": "2008-10-17",
                    "Statement": [
                        {
                            "Sid": "AllowPublicRead",
                            "Effect": "Allow",
                            "Principal": {
                                "AWS": "*"
                            },
                            "Action": "s3:GetObject",
                            "Resource": "arn:aws:s3:::" + bucket_name + "/*",
                            "Condition": {
                                "IpAddress": {
                                    "aws:SourceIp": iplist
                                }
                            }
                        }
                    ]
                }
                update_policy = s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(new_policy))


    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
            pass
        elif e.response['Error']['Code'] == 'ServiceFailure:':
            t.q_status_send(detail=e, status=c.ERROR)
            log.debug('Error checking entity - service unavailable.')
            return t.error(e)
        else:
            print(e.response)


def acl_fixer(bucket_name):
    try:
        print('ACL fixer')
        s3 = session.client('s3')
        bucket_acl_response = s3.get_bucket_acl(
            Bucket=bucket_name
        )
        temp_acl = bucket_acl_response
        loop = True

        while loop:
            loop = False
            for grant in bucket_acl_response['Grants']:
                if 'URI' in grant['Grantee']:
                    if grant['Grantee']['URI'] == 'http://acs.amazonaws.com/groups/global/AllUsers':
                        bucket_acl_response['Grants'].remove(grant)
                        loop = True
        acl = {'Owner': bucket_acl_response['Owner'], 'Grants': bucket_acl_response['Grants']}

        new_acl = s3.put_bucket_acl(
            Bucket=bucket_name, AccessControlPolicy=acl
        )

        # Now attach a bucket policy to the bucket with the IP restrictions.
        add_basic_bucket_policy(bucket_name)

    except ClientError as e:
        print(e.response)
    
def lambda_handler(event, context):
    results = assess(event, context)
    print(results)