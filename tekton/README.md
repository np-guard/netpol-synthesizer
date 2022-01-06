# k8s-netpol-synthesize

This Task automates the generation of Kubernetes NetworkPolicies for a given application. It will first scan your repository for YAML files which define various Kubernetes resources (e.g., Deployments, Services, ConfigMaps). It will then analyze these files and extract all network connections required for your application to work. Finally, this Task will synthesise K8s NetworkPolicies that allow these connections and nothing more.

This Task is part of a wider attempt to provide [shift-left automation for generating and maintaining Kubernetes Network Policies](https://np-guard.github.io/).


## Install the Task

```
kubectl apply -f https://raw.githubusercontent.com/np-guard/netpol-synthesizer/master/tekton/netpol-synthesis-task.yaml
```

## Parameters
* **corporate-policies**: An array of corporate policy files to check against (either as GitHub URLs or as paths under workspace).
* **output-dir**: The directory under 'source' workspace, into which the YAML file with the synthesized NetworkPolicies will be written

## Workspaces
* **source**: A [Workspace](https://github.com/tektoncd/pipeline/blob/main/docs/workspaces.md) containing the application YAMLs to analyze.

## Platforms

The Task can be run on `linux/amd64`.

## Usage

This TaskRun runs the Task to verify the connectivity of a previously checked-out app against two corporate policies.

```yaml
apiVersion: tekton.dev/v1beta1
kind: TaskRun
metadata:
  name: synthesize-netpols
spec:
  taskRef:
    name: k8s-netpol-synthesize
  params:
  - name: corporate-policies
    value:
    - https://github.com/np-guard/baseline-rules/blob/master/examples/restrict_access_to_payment.yaml
    - https://github.com/np-guard/baseline-rules/blob/master/examples/ciso_denied_ports.yaml
  workspaces:
  - name: source
    persistentVolumeClaim:
      claimName: my-source
```

For a more complete example, showing how to use the synthesized NetworkPolicies to open a GitHub PR, see [this PipelineRun](netpol-synthesis-plr.yaml).
