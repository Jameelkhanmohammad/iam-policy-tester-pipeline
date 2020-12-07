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

    def test_dynamo(self):
        policy1 = read_file("dynamo_policy.json")

        actions = json.loads(read_file("dynamo_actions.json"))
        resources = json.loads(read_file("dynamo_resources.json"))
        evaluation_results = self.iam_client.simulate_custom_policy(

            PolicyInputList=[policy1],
            ActionNames=actions,
            ResourceArns=resources)
        pprint.pprint(evaluation_results)
        failed = [x for x in evaluation_results["EvaluationResults"] if isDenied(x)]
        self.assertEqual(evaluation_results["EvaluationResults"][0]["EvalDecision"], "allowed", "Few actions not allowed")
        self.assertEqual(len(failed), 0, "Some actions were denied\n" + prettyPrintResults(failed))

    def test_dynamo_policy(self):
        policy = read_file("dynamo_policy.json")
        actions = json.loads(read_file("dynamo_actions.json"))
        evaluation_results = self.iam_client.simulate_custom_policy(
            PolicyInputList=[policy],
            ActionNames=actions)
        pprint.pprint(evaluation_results)
        failed = [x for x in evaluation_results["EvaluationResults"] if isDenied(x)]
        self.assertLessEqual(len(failed), 0, "Some actions were denied\n" + prettyPrintResults(failed))


if __name__ == '__main__':
    unittest.main()
