# netpol-synthesizer
This application takes a JSON file, describing the connectivity in a given Kubernetes cluster,
and produces a set of Kubernetes NetworkPolicies that allow only the specified connectivity
and nothing more.

### Requirements:

* Python 3.7 or above

### Installation:
1. `git clone --recurse-submodules git@github.com:shift-left-netconfig/netpol-synthesizer.git`
1. `cd netpol-synthesizer`   
1. `python3 -m venv venv`
1. `source venv/bin/activate.csh` (the exact script may depend on the shell you are using) 
1. `pip install -r requirements.txt`

### Usage:
```commandline
python src/netpol_synth.py [-o <output_file>] [-b baseline_rules_file] <connectivity_file>
```
* `connectivity_file` is the path to a JSON file describing connectivity. This should be the output of running the [Network Topology Analyzer](https://github.com/shift-left-netconfig/cluster-topology-analyzer).
* `output_file` *(optional)* is a path to output file where the resulting NetworkPolicy resources will be dumped (in YAML format). If omitted, output will be sent to stdout.
* `baseline_rules_file` is a yaml file containing a list of baseline rules. See [these examples](https://github.com/shift-left-netconfig/baseline-rules/tree/master/examples)

For example:
```commandline
 python src/netpol_synth.py -o test.yaml -b baseline-rules/examples/allow_load_generation.yaml tests/connectivity_jsons/microservices-demo.json
```
