# Reviewer Scope

This anonymous-artifact branch keeps the CRSBench paths needed to exercise the
paper's claimed functionality.

## Reviewer Paths

- Local queue-backed run:
  [Install](../getting-started/install.md),
  [Configuration](../getting-started/configuration.md), and
  [First Experiment](../getting-started/first-experiment.md)
- Discovery-only OSS-Fuzz workflow:
  [Discovery-Only OSS-Fuzz](../guides/experiments/discovery-only.md)
- Distributed worker/evaluator workflow:
  [Distributed Experiments](../guides/experiments/distributed.md)
- Managed cloud workflow on GCE:
  [GCE Cloud Orchestration](../guides/experiments/gce-cloud-orchestration.md)
- Verification and adapter contracts:
  [OSS-CRS Interface](./oss-crs-interface.md) and
  [Evaluation Contract](../design/evaluation/evaluation.md)

## Kept

- Hugging Face dataset download and packaging flow
- OSS-CRS adapter integration
- Queue-backed distributed execution with Valkey/RQ
- Managed GCE orchestration and SSH-managed worker deployment
- cgroup resource isolation and LiteLLM accounting support
- Replay-safe incremental build and verification paths
- Discovery-only OSS-Fuzz execution flow
- TLA+ models and related distributed-control-plane specifications

## Third-Party Provenance Kept

- `oss-crs/` remains third-party and is not anonymized here.
- Atlantis / Team-Atlanta provenance is kept where it reflects a genuine
  upstream dependency or published artifact source.
- Benchmark payloads continue to come from the configured Hugging Face dataset
  rather than being vendored into this branch.
