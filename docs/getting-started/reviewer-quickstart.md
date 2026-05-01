# Reviewer Quickstart

Use this page when you want the shortest path through the anonymous artifact.

## 1. Understand the Cut Line

Start with [Reviewer Scope](../reference/reviewer-scope.md). It lists the
kept workflows and the provenance boundaries relevant to this branch.

## 2. Bootstrap Locally

Follow:

1. [Install](./install.md)
2. [Configuration](./configuration.md)
3. [First Experiment](./first-experiment.md)

That path exercises the local queue-backed runtime without requiring managed
cloud resources.

## 3. Pick a Capability to Validate

- Discovery-only workflow:
  [Discovery-Only OSS-Fuzz](../guides/experiments/discovery-only.md)
- Distributed worker/evaluator workflow:
  [Distributed Experiments](../guides/experiments/distributed.md)
- Managed cloud workflow on GCE:
  [GCE Cloud Orchestration](../guides/experiments/gce-cloud-orchestration.md)

## 4. Example Config Sources

Use the sanitized presets indexed in
[Example Configs](../reference/example-configs.md). Reviewer workflows should
prefer those checked-in examples over ad hoc local notes. For managed cloud
runs, the generic GCE guide shows a public `git+https` bootstrap path, while
the checked-in `experiment-configs/cloud-testing/*` presets exercise a
`git+ssh` plus deploy-key bootstrap path. Keep
`cloud.defaults.crsbench_install_spec` and any deploy-key settings aligned with
whichever mode you choose.
