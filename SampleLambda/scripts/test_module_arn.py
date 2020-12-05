import unittest
import json
import boto3
import pprint


class TestPolicies(unittest.TestCase):
    def test_policy(self):
        policy = readFile("cli_policy.json")
        ActionNames = json.loads(readFile("actions.json"))
        ResourceArns = readFile("resource.txt")


def readFile(file_name):
    with open(file_name, "r") as f:
        read_data = f.read()
    return read_data


def simulatePrincipalPolicy(source, actions, policies):
    iam_client = boto3.client("iam")
    response = iam_client.simulate_custom_policy(
    policy=policies,
    ActionNames=actions,
    ResourceArns=source,
    # CallerArn="arn:aws:iam::226518205592:user/Jameel-Tools",

)
    return response["EvaluationResults"]


def isDenied(evaluationResults):
    return evaluationResults["EvalDecision"] != "allowed"


def isDenied(evaluationResults):
    return evaluationResults["EvalDecision"] != "allowed"


#pprint.pprint(response)


def prettyPrintResults(evaluationResults):
    """prettyPrintResults returns a string formatting the results of a simulation evaluation result"""
    output = ""
    for er in evaluationResults:
        message = (
            f"Evaluated Action Name: {er['EvalActionName']}\n"
            f"\tEvaluated Resource name: {er['EvalResourceName']}\n"
            f"\tDecision: {er['EvalDecision']}\n"
        )
        output += message
    return output


if __name__ == "__main__":
    unittest.main()
