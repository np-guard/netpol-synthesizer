#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

"""
This module allows verifying a set of network policies against a set of baseline rules
"""

import argparse
import subprocess
import yaml
import os
from pathlib import Path
from baseline_rule import BaselineRules, BaselineRuleAction


class NetpolVerifier:
    def __init__(self, netpol_file, baseline_rules_file, repo):
        self.netpol_file = netpol_file
        self.baseline_rules = BaselineRules(baseline_rules_file)
        self.repo = Path(repo).absolute()

    def verify(self):
        nca_python_path = Path(Path(__file__).parent.absolute(), '..', '..',
                               'network-config-analyzer', 'venv', 'Scripts', 'python')
        nca_path = Path(Path(__file__).parent.absolute(), '..', '..',
                        'network-config-analyzer', 'network-config-analyzer', 'nca.py')
        fixed_args = [nca_python_path, nca_path, '--base_np_list', self.netpol_file, '--pod_list', self.repo, '--ns_list',
                    self.repo]

        for rule in self.baseline_rules:
            rule_filename = f'{rule.name}.yaml'
            with open(rule_filename, 'w') as baseline_file:
                yaml.dump(rule.to_netpol(), baseline_file)
            query = '--forbids' if rule.action == BaselineRuleAction.deny else '--permits'
            nca_args = fixed_args + [query, rule_filename]
            nca_run = subprocess.run(nca_args, capture_output=True, text=True)
            if nca_run.returncode == 0:
                print(f'\nrule {rule.name} is satisfied')
            else:
                print(f'\nrule {rule.name} is violated')
                print('\n'.join(str(nca_run.stdout).split('\n')[3:5]))
            os.remove(rule_filename)


def netpol_verify_main(args=None):
    """
    This is the main entry point to verifying policies against baseline rules
    :param args: Commandline arguments
    :return: None
    """
    parser = argparse.ArgumentParser(description='A verifier for K8s Network Policies')
    parser.add_argument('netpol_file', type=str, help='A yaml file containing k8s NetworkPolicy resources')
    parser.add_argument('--baseline', '-b', type=open, metavar='FILE', action='append',
                        help='A baseline-requirements file')
    parser.add_argument('--repo', '-r', type=str, metavar='REPOSITORY', help="Repository with the app's deployments")
    args = parser.parse_args(args)

    NetpolVerifier(args.netpol_file, args.baseline, args.repo).verify()


if __name__ == "__main__":
    netpol_verify_main()
