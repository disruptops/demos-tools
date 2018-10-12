import boto3
import json

# Updates needed- IPV6, an IP range that includes port 22
# Also add fix in case requested IP range is already in there

def update_security_group(event, group, existingIpPermission, port, new_range):
    if "clickType" not in event:
        ec2 = boto3.client('ec2', region_name=event)
    else:
        ec2 = boto3.client('ec2')
    sub_range = []
    for curIP in existingIpPermission['IpRanges']:
        if curIP['CidrIp'] != '0.0.0.0/0':
            sub_range.append(curIP)
    sub_range.append(new_range)
    remove_rule = ec2.revoke_security_group_ingress(
    GroupId=group,
    IpPermissions=[
            {'IpProtocol': 'tcp',
             'FromPort': port,
             'ToPort': port,
             'IpRanges': existingIpPermission['IpRanges']}
                ])
    add_rule = ec2.authorize_security_group_ingress(
    GroupId=group,
    IpPermissions=[
            {'IpProtocol': 'tcp',
             'FromPort': port,
             'ToPort': port,
             'IpRanges': sub_range}
                ])
    
def lambda_handler(event, context):
    if "clickType" in event:
        ec2 = boto3.client('ec2')
        if event['clickType'] == 'DOUBLE':
            mode = "remediate"
            print(mode)
        elif event['clickType'] == 'SINGLE':
            mode = "alert"
            print(mode)
    else:
        mode = "alert"
        ec2 = boto3.client('ec2', region_name='us-west-2')
        print(mode)

    match_groups = []
    group_count = 0
#    try:
    secgroups = ec2.describe_security_groups(Filters=[
        {'Name': 'ip-permission.cidr', 'Values': ['0.0.0.0/0'] }
    ]
    )
    for curgroup in secgroups['SecurityGroups']:
        for permission in curgroup['IpPermissions']:
            if 'FromPort' in permission:
                if permission['FromPort'] == 22:
                    for cidr in permission['IpRanges']:
                        if cidr['CidrIp'] == '0.0.0.0/0':
                            print(permission)
                            match_groups.append(curgroup)
                            group_count += 1
                            new_range = {'CidrIp': '192.168.0.1/32'}
                            if mode == "remediate":
                                update_security_group(event, curgroup['GroupId'], permission, 22, new_range)
#    except Exception as e:
 #      return ('failed')
    print("matches")
    print(match_groups)
    #Match Security Groups to Instances.
    #network-interface.group-id - The ID of a security group associated with the network interface.
    instance_count = 0
    instance_filter = {'Name': 'network-interface.group-id'}
    instance_filter.setdefault('Values', [])
    sg_names = {}
    for sec_grp in match_groups:
        instance_filter['Values'].append(sec_grp['GroupId'])
        sg_names[sec_grp['GroupId']] = sec_grp['GroupName']
    print('SGs', json.dumps(match_groups))
    find_instances = ec2.describe_instances(
        Filters=[
            instance_filter
        ],
        DryRun=False,
        #MaxResults=123,
        #NextToken='string'
    )
    #print(find_instances)
    detail = {'instances': []}
    for ec2reservations in find_instances['Reservations']:
        for theinstances in ec2reservations['Instances']:
            detail['instances'].append({
                'InstanceId': theinstances.get('InstanceId'),
                'SubnetId': theinstances.get('SubnetId'),
                'Tags': theinstances.get('Tags'),
                'State': theinstances.get('State')
            })
            instance_count += 1
    if detail['instances']:
        status = "FAIL"
    else:
        status = "SUCCESS"
    if mode == "alert":
        sms_string = f"ISSUE FOUND: {instance_count} administrative instances exposed. There are {group_count} security groups with port 22 open to the Internet. **Click Easy Button twice to remediate**" 
    elif mode == "remediate":
        sms_string = f"ISSUE AUTOMATICALLY REMEDIATED: {instance_count} administrative instances were exposed. There were {group_count} security groups with port 22 open to the Internet. **Security Groups updated to only allow approved access**" 
    client = boto3.client('sns')
    response = client.publish(
        TargetArn='arn:aws:sns:us-west-2:935440313651:SecurityGroupAlert',
        Message=json.dumps({'default': json.dumps(detail),
                        'sms': sms_string,
                        'email': json.dumps(detail)}),
        Subject='Admin servers exposed',
     MessageStructure='json'
    )