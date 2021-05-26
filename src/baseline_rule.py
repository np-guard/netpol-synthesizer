#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

"""
A module for storing and querying baseline rules
"""
from enum import Enum
import yaml
from selector import Selector, SelectorOp, IpSelector


class BaselineRuleAction(Enum):
    """
    Allowed actions for a baseline rule
    """
    deny = 0
    allow = 1


class BaselineRule:
    """
    This class holds all relevant information about a baseline rule and provides several methods to query it
    """
    def __init__(self, rule_record):
        self.name = rule_record.get('name', '<no name>')
        print(f'processing rule {self.name}')
        self.description = rule_record.get('description', '')
        self.action = BaselineRuleAction[rule_record.get('action', 'allow')]
        self.source = Selector.parse_selectors(rule_record.get('from', ''))
        self.target = Selector.parse_selectors(rule_record.get('to', ''))
        self.protocol = rule_record.get('protocol')
        self.port_min = rule_record.get('port_min')
        self.port_max = rule_record.get('port_max')

    def matches_connection(self, source_labels, target_labels, port_list):
        """
        Check whether this rule matches a given connection (and therefore allows/denies it)
        :param dict source_labels: The label of the source deployment
        :param dict target_labels: The labels of the target deployment
        :param list port_list: A list of ports on which connections should be made
        :return: Whether the rule matched the connection
        :rtype: bool
        """
        if not self.matches_source(source_labels):
            return False
        if not self.matches_target(target_labels):
            return False

        for port in port_list:
            port_num = port.get('port')
            protocol = port.get('protocol', 'TCP')
            protocol_match = (not self.protocol or self.protocol == protocol)
            port_min_match = (not self.port_min or port_num >= self.port_min)
            port_max_match = (not self.port_max or port_num <= self.port_max)
            if protocol_match and port_min_match and port_max_match:
                return True

        return not bool(port_list)

    @staticmethod
    def _matches_selectors(labels, selectors):
        if isinstance(selectors, IpSelector):
            return False
        return all(selector.matches(labels) for selector in selectors)

    def matches_source(self, labels):
        """
        Check whether the given set of labels match the rule source
        :param dict labels: The labels to match
        :return: True if the labels match the rule source. False otherwise
        :rtype: bool
        """
        return BaselineRule._matches_selectors(labels, self.source)

    def matches_target(self, labels):
        """
        Check whether the given set of labels match the rule target
        :param dict labels: The labels to match
        :return: True if the labels match the rule target. False otherwise
        :rtype: bool
        """
        return BaselineRule._matches_selectors(labels, self.target)

    @staticmethod
    def _selectors_as_netpol_peer(selectors):
        if not selectors:
            return {}
        if isinstance(selectors, IpSelector):
            return {'ipBlock': selectors.get_cidr()}
        if all(len(selector.values) == 1 and selector.operator == SelectorOp.IN for selector in selectors):
            sel = {'matchLabels': {selector.key: selector.values[0] for selector in selectors}}
        else:
            sel = {'matchExpressions': [selector.convert_to_label_selector_requirement() for selector in selectors]}
        return {'podSelector': sel}

    def sources_as_netpol_peer(self):
        """
        :return: the source field as a k8s NetworkPolicyPeer record
        :rtype: dict
        """
        return self._selectors_as_netpol_peer(self.source)

    def targets_as_netpol_peer(self):
        """
        :return: the target field as a k8s NetworkPolicyPeer record
        :rtype: dict
        """
        return self._selectors_as_netpol_peer(self.target)

    def get_port_array(self):
        """
        :return: the port range specified in the baseline rule as a list of k8s port records
        :rtype: list
        """
        if not self.port_min:
            return []
        ports_array = []
        for port in range(self.port_min, self.port_max + 1):
            port_rec = {'protocol': self.protocol} if self.protocol else {}
            port_rec['port'] = port
            ports_array.append(port_rec)

        return ports_array

    def to_netpol(self):
        """
        :return: A k8s NetworkPolicy resource representing the connections specified by the rule
        :rtype: dict
        """
        is_ingress_policy = not isinstance(self.target, IpSelector)
        policy_type = 'Ingress' if is_ingress_policy else 'Egress'
        policy_selector = self._selectors_as_netpol_peer(self.target if is_ingress_policy else self.source) or \
            {'podSelector': {}}
        policy_spec = {
            'policyTypes': [policy_type]
        }
        policy_spec.update(policy_selector)
        rule_to_add = {'ports': self.get_port_array()}
        if is_ingress_policy:
            from_selector = self._selectors_as_netpol_peer(self.source)
            if from_selector:
                rule_to_add.update({'from': [from_selector]})
            policy_spec['ingress'] = [rule_to_add]
        else:
            to_selector = self._selectors_as_netpol_peer(self.target)
            if to_selector:
                rule_to_add.update({'to': [to_selector]})
            policy_spec['egress'] = [rule_to_add]

        return {
            'apiVersion': 'networking.k8s.io/v1',
            'kind': 'NetworkPolicy',
            'metadata': {'name': self.name},
            'spec': policy_spec
        }


class BaselineRules(list):
    """
    Simply a collection of BaselineRule objects
    """
    def __init__(self, baseline_files):
        super().__init__()
        for baseline_file in baseline_files or []:
            for rule_record in yaml.load(baseline_file, Loader=yaml.SafeLoader):
                self.append(BaselineRule(rule_record))
