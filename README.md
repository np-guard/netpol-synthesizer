# netpol-synthesizer
This application takes a JSON file, describing the connectivity in a given Kubernetes cluster,
and produces a set of policies (Kubernetes NetworkPolicies or Istio AuthorizationPolicies) that allow only the specified connectivity
and nothing more.

### Requirements:

* Python 3.8 or above

### Installation:
```commandline
git clone --recurse-submodules https://github.com/np-guard/netpol-synthesizer.git
cd netpol-synthesizer
python3 -m venv venv
source venv/bin/activate.csh  # the exact script may depend on the shell you are using
pip install -r requirements.txt
```

### Usage:
```commandline
python src/netpol_synth.py [-o <output_file>] [-b baseline_rules_file] [--policy_type=<policy_type_str>] <connectivity_file>
```
* `connectivity_file` is the path to a JSON file describing connectivity. This should be the output of running the [Network Topology Analyzer](https://github.com/np-guard/cluster-topology-analyzer).
* `output_file` *(optional)* is a path to output file where the resulting policy resources will be dumped (in YAML format). If omitted, output will be sent to stdout.
* `baseline_rules_file` is a yaml file containing a list of baseline rules. See [these examples](https://github.com/np-guard/baseline-rules/tree/master/examples)
* `policy_type_str` is one of the values: `['k8s', 'istio']`, *default:* `k8s`

For example:
```commandline
 python src/netpol_synth.py -o test.yaml -b baseline-rules/examples/allow_load_generation.yaml tests/connectivity_jsons/microservices-demo.json
```
