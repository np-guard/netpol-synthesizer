#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

"""
This module converts a file describing discovered connectivity in a K8s cluster into a set of k8s NetworkPolicies
"""
import argparse
from pathlib import Path
import sys
from dataclasses import dataclass, field
from typing import Optional
import yaml

base_dir = Path(__file__).parent.resolve()
common_services_dir = (base_dir / '../baseline-rules/src').resolve()
sys.path.insert(0, str(common_services_dir))

from baseline_rule import BaselineRules, BaselineRuleAction


class NoAliasDumper(yaml.SafeDumper):
    """
    This class is needed to avoid aliases and references in the generated yaml file
    (so that users will be able to copy & paste individual NetworkPolicies)
    """
    def ignore_aliases(self, data):
        return True


@dataclass()
class DeploymentLinks:
    """
    A class for holding information about a given deployment for which we want to create NetworkPolicy
    """
    name: str
    namespace: str = ''
    selectors: Optional[dict] = None
    labels: dict = field(default_factory=dict)
    ingress_conns: list = field(default_factory=list)
    egress_conns: list = field(default_factory=list)


class NetpolSynthesizer:
    """
    This is the main class for the conversion. Call its synthesize() method to generate k8s NetworkPolicy resources
    """
    def __init__(self, connectivity_file, baseline_files):
        self.deployments = {}
        self.baseline_rules = BaselineRules(baseline_files)
        self._process_connectivity_file(connectivity_file)
        self._add_must_allow_connections()

    def _process_connectivity_file(self, connectivity_file):
        """
        Scans the given connectivity file and extracts deployment endpoints and required connections between them
        :param connectivity_file: A file opened for reading, describing the required connectivity
        :return: None
        """
        internet_src = DeploymentLinks('Outside internet')
        namespace_src = DeploymentLinks('Inside namespace', '', {'podSelector': {}})

        for element in yaml.load_all(connectivity_file, Loader=yaml.SafeLoader):
            if not isinstance(element, list):
                continue
            for connection in element:
                src_deploy = self._find_or_add_deployment(connection['source']['Resource'])
                tgt_deploy = self._find_or_add_deployment(connection['target']['Resource'])
                links = connection['link']['resource']
                port_list = self._links_to_port_list(links.get('network'))
                if links.get('type') == 'LoadBalancer':
                    src_deploy = internet_src  # A Service of type LoadBalancer exposes the target to the internet
                elif not src_deploy.name:
                    src_deploy = namespace_src

                violated_baseline_rule = self._allowed_by_baseline(src_deploy.labels, tgt_deploy.labels, port_list)
                if violated_baseline_rule:
                    print(f'Warning: required connection from {src_deploy.name} to {tgt_deploy.name} '
                          f'is disallowed by baseline rule {violated_baseline_rule}')
                else:
                    if src_deploy not in [internet_src, namespace_src]:
                        self.deployments[src_deploy.name].egress_conns.append((tgt_deploy.selectors, port_list))
                    self.deployments[tgt_deploy.name].ingress_conns.append((src_deploy.selectors, port_list))

    def _find_or_add_deployment(self, resource):
        """
        Adds a deployment that appears as source or target in the connectivity file
        :param dict resource: deployment parameters
        :return: An instance of DeploymentLinks for the given deployment
        :rtype: DeploymentLinks
        """
        name = resource['name']
        if not name:
            return DeploymentLinks('')  # empty src

        if name not in self.deployments:
            namespace = resource.get('namespace', '')
            sel = self._selector_array_to_pod_selector(resource.get('selectors', []))
            labels = resource.get('labels', {})
            self.deployments[name] = DeploymentLinks(name, namespace, sel, labels)
        return self.deployments[name]

    def _allowed_by_baseline(self, source_labels, target_labels, port_list):
        for rule in self.baseline_rules:
            if rule.action == BaselineRuleAction.deny and \
                    rule.matches_connection(source_labels, target_labels, port_list):
                return rule.name
        return None

    @staticmethod
    def _selector_array_to_pod_selector(sel_array):
        res = {}
        for sel in sel_array or []:
            col_pos = sel.find(':')
            key = sel[:col_pos]
            val = sel[col_pos+1:]
            res[key] = val
        return {'podSelector': {'matchLabels': res}}

    @staticmethod
    def _links_to_port_list(links):
        return [{'port': link.get('target_port')} for link in links]

    def _add_must_allow_connections(self):
        for deploy in self.deployments.values():
            for rule in self.baseline_rules:
                if not rule.action == BaselineRuleAction.allow:
                    continue
                if rule.matches_source(deploy.labels):
                    deploy.egress_conns.append((rule.targets_as_netpol_peer(), rule.get_port_array()))
                if rule.matches_target(deploy.labels):
                    deploy.ingress_conns.append((rule.sources_as_netpol_peer(), rule.get_port_array()))

    @staticmethod
    def _xgress_conns_to_rules(conns, is_ingress):
        res_rules = []
        seen_rules = set()
        for conn in conns:
            rule = {'ports': conn[1]} if conn[1] else {}
            if conn[0]:
                selector_key = 'from' if is_ingress else 'to'
                rule[selector_key] = [conn[0]]
            rule_yaml = yaml.dump(rule)
            if rule_yaml in seen_rules:
                continue
            seen_rules.add(rule_yaml)
            res_rules.append(rule)

        if conns and not is_ingress:
            allow_dns = {'to': [{'namespaceSelector': {}, 'podSelector': {'matchLabels': {'k8s-app': 'kube-dns'}}}],
                         'ports': [{'port': 53, 'protocol': 'UDP'}]}
            res_rules.append(allow_dns)

        return res_rules

    def synthesize(self, output_file):
        """
        Generates NetworkPolicies in yaml format based on the analysis done in the ctor.
        If output file is specified, the output is dumped into the file. Otherwise, stdout is used
        :param output_file: A file opened for writing
        :return: None
        """
        netpols = []
        for deployment in self.deployments.values():
            metadata = {'name': deployment.name + '-netpol'}
            if deployment.namespace:
                metadata['namespace'] = deployment.namespace
            spec = {'podSelector': deployment.selectors['podSelector'],
                    'policyTypes': ['Ingress', 'Egress'],
                    'ingress': self._xgress_conns_to_rules(deployment.ingress_conns, True),
                    'egress': self._xgress_conns_to_rules(deployment.egress_conns, False)}
            netpol = {'apiVersion': 'networking.k8s.io/v1',
                      'kind': 'NetworkPolicy',
                      'metadata': metadata,
                      'spec': spec}
            netpols.append(netpol)

        if output_file:
            yaml.dump_all(netpols, output_file, Dumper=NoAliasDumper)
            print(f'\nNetwork Policies were successfully written to {output_file.name}')
        else:
            print(yaml.dump_all(netpols))


def netpol_synth_main(args=None):
    """
    This is the main entry point to generating policies
    :param args: Commandline arguments
    :return: None
    """
    parser = argparse.ArgumentParser(description='A generator for K8s Network Policies')
    parser.add_argument('connectivity_file', type=open, help='A json input file describing connectivity')
    parser.add_argument('--baseline', '-b', type=str, metavar='FILE', action='append',
                        help='A baseline-requirements file')
    parser.add_argument('--output', '-o', type=argparse.FileType('w'), metavar='FILE',
                        help='Output file for NetworkPolicy resources')
    args = parser.parse_args(args)

    NetpolSynthesizer(args.connectivity_file, args.baseline).synthesize(args.output)


if __name__ == "__main__":
    netpol_synth_main()
