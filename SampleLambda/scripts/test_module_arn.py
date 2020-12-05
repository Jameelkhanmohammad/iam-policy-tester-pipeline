from datetime import datetime

import boto3
import pprint
iam_client=boto3.client("iam")

def readFile(file_name):
    with open(file_name, "r") as f:
        read_data = f.read()
    return read_data


policy = readFile("cli_policy.json")
response=iam_client.simulate_custom_policy(
            PolicyInputList=[policy],
            ActionNames=['dynamodb:CreateBackup'],
            ResourceArns=['arn:aws:dynamodb:us-east-1:226518205592:table/new_table'],
            # CallerArn="arn:aws:iam::226518205592:user/Jameel-Tools",

)
pprint.pprint(response)