import unittest
import boto3
import pprint
import json


def read_file(file_name: str):
    with open(file_name, "r") as f:
        read_data = f.read()
    return read_data


def isDenied(evaluationResults):
    return evaluationResults["EvalDecision"] != "allowed"


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


class TestStringMethods(unittest.TestCase):

    def setUp(self):
        self.iam_client = boto3.client("iam")

    def test_simulate_principal_resource_unrestricted_deny(self):
        policy = read_file("iam_policy.json")
        actions = json.loads(read_file("actions.json"))
        evaluation_results = self.iam_client.simulate_principal_policy(
            PolicySourceArn =read_file("source.txt"),
            PolicyInputList=[policy],
            ActionNames=actions
        )
        pprint.pprint(evaluation_results)
        failed = [x for x in evaluation_results["EvaluationResults"] if isDenied(x)]
        self.assertEqual(evaluation_results["EvaluationResults"][0]["EvalDecision"], "implicitDeny")
        self.assertEqual(len(failed), 1, "Some actions were denied\n" + prettyPrintResults(failed))

    def test_simulate_principal_resource_restricted_deny(self):
        policy1 = read_file("iam_policy.json")
        actions = json.loads(read_file("actions.json"))
        resources = json.loads(read_file("resources.json"))
        evaluation_results = self.iam_client.simulate_principal_policy(
            PolicySourceArn=read_file("source.txt"),
            PolicyInputList=[policy1],
            ActionNames=actions,
            ResourceArns=resources)
        pprint.pprint(evaluation_results)
        failed = [x for x in evaluation_results["EvaluationResults"] if isDenied(x)]
        self.assertEqual(evaluation_results["EvaluationResults"][0]["EvalDecision"], "explicitDeny")
        self.assertEqual(len(failed), 1, "Some actions were denied\n" + prettyPrintResults(failed))

    def test_simulate_principal_resource_unrestricted_allow(self):
        actions = json.loads(read_file("actions.json"))
        source = read_file("source.txt")
        evaluation_results = self.iam_client.simulate_principal_policy(
            PolicySourceArn=source,
            ActionNames=actions)
        pprint.pprint(evaluation_results)
        failed = [x for x in evaluation_results["EvaluationResults"] if isDenied(x)]
        self.assertEqual(evaluation_results["EvaluationResults"][0]["EvalDecision"], "allowed", "Few actions not allowed")
        self.assertEqual(len(failed), 0, "Some actions were denied\n" + prettyPrintResults(failed))

    def test_simulate_principal_resource_restricted_allow(self):
        actions = json.loads(read_file("actions.json"))
        policy1 = read_file("iam_policy.json")
        #policy2 = read_file("s3_policy.json")
        resources = json.loads(read_file("resources.json"))
        source = read_file("source.txt")
        # collect all policy resources in a list
        test = json.loads(policy1)
        #test1 = json.loads(policy2)
        all_resources = []
        for each in test['Statement']:
            all_resources.append(each['Resource'])


        #for each in test1['Statement']:
            #all_resources.append(each['Resource'])

        # check on resource and policy
        self.assertEqual(all_resources,resources, "resources are not matching ")

        evaluation_results = self.iam_client.simulate_principal_policy(
            PolicySourceArn=source,
            PolicyInputList=[policy1],
            #PolicyInputList=[policy1, policy2],
            ActionNames=actions,
            ResourceArns=resources
        )

        pprint.pprint(evaluation_results)
        failed = [x for x in evaluation_results["EvaluationResults"] if isDenied(x)]
        self.assertEqual(evaluation_results["EvaluationResults"][0]["EvalDecision"], "allowed", "Few actions not allowed")
        self.assertEqual(len(failed), 0, "Some actions were denied\n" + prettyPrintResults(failed))

    def test_simulate_custom_resource_restricted_allow(self):
        policy = read_file("iam_policy.json")
        actions = json.loads(read_file("actions.json"))
        resources = json.loads(read_file("resources.json"))
        evaluation_results = self.iam_client.simulate_custom_policy(
            PolicyInputList=[policy],
            ActionNames=actions,
            ResourceArns=resources)
        pprint.pprint(evaluation_results)
        failed = [x for x in evaluation_results["EvaluationResults"] if isDenied(x)]
        self.assertEqual(evaluation_results["EvaluationResults"][0]["EvalDecision"], "allowed", "Few actions not allowed")
        self.assertEqual(len(failed), 0, "Some actions were denied\n" + prettyPrintResults(failed))

    def test_simulate_custom_resource_unrestricted_allow(self):
        policy = read_file("iam_policy.json")
        actions = json.loads(read_file("actions.json"))
        evaluation_results = self.iam_client.simulate_custom_policy(
            PolicyInputList=[policy],
            ActionNames=actions)
        pprint.pprint(evaluation_results)
        failed = [x for x in evaluation_results["EvaluationResults"] if isDenied(x)]
        self.assertEqual(evaluation_results["EvaluationResults"][0]["EvalDecision"], "allowed", "Few actions not allowed")
        self.assertLessEqual(len(failed), 0, "Some actions were denied\n" + prettyPrintResults(failed))


if __name__ == '__main__':
    unittest.main()