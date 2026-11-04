# ICSE Hybrid CRS Random-Sample Evaluation

The ICSE major revision requests a hybrid CRS evaluation whose benchmark
selection is independent of standalone outcomes and covers both languages
and both modes. This experiment samples whole benchmark IDs from the
canonical `crsbench/all` suite, without reading experiment results. The
original outcome-selected hybrid targets are not the sampling population.

## Sampling protocol

The frozen population contains 124 non-sanity benchmarks. There are no
additional exclusions. Language comes from `project.yaml`, with C/C++ grouped
as `c` and JVM/Java as `jvm`. Mode follows the experiment runtime's `auto`
policy: delta when `delta_mode` is available, otherwise full. Benchmarks
supporting both modes therefore belong to the delta stratum, rather than
appearing twice in the population.

| Stratum | Population | Selected benchmarks |
| --- | ---: | ---: |
| C/C++ delta | 46 | 7 |
| C/C++ full | 17 | 7 |
| JVM delta | 41 | 7 |
| JVM full | 20 | 7 |
| Total | 124 | 28 |

This is a balanced stratified sample, not a proportionate sample. Report
per-stratum results; estimates for the whole population require weighting by
the population stratum sizes. Benchmark IDs are the sampling units, so
projects with multiple benchmark IDs can appear more than once.

Reproduce the frozen selection from the repository root:

```bash
uv run crsbench benchmark sample \
  --source-suite benchmark-suites/crsbench/all.yaml \
  --benchmarks-root benchmarks \
  --seed 20261104 \
  --per-stratum 7 \
  --name icse/hybrid-random \
  --release-date 11.04.2026 \
  --output benchmark-suites/icse/hybrid-random.yaml \
  --manifest experiment-configs/icse/hybrid-random-sampling.json
```

The command samples without replacement from sorted IDs in the fixed order
`c/delta`, `c/full`, `jvm/delta`, `jvm/full`, using Python 3.12
`random.Random(seed).sample`. It writes a runnable suite and a JSON audit
manifest containing every population ID, selections, seed, stratum sizes,
and SHA-256 fingerprints of the source suite and metadata. Existing outputs
are protected; use alternate output paths to verify reproduction, or
`--force` to intentionally replace them. Missing/invalid metadata,
unsupported languages, filtered source-suite selectors, and insufficient
stratum sizes fail the command rather than silently changing eligibility.

The frozen suite is [hybrid-random.yaml](../../benchmark-suites/icse/hybrid-random.yaml);
the audit record is [hybrid-random-sampling.json](../../experiment-configs/icse/hybrid-random-sampling.json).
Do not redraw after inspecting performance. Record infrastructure failures
and retry the same selected tasks; do not replace them with easier targets.

## Main experiment

Use [gce-sample-hybrid-random-finding.yaml](../../experiment-configs/icse/gce-sample-hybrid-random-finding.yaml).
It preserves the earlier ICSE hybrid configuration's model
(`claude-opus-4-6`), three trials, 8-hour finding window, $30 per-trial LLM
budget, seed input, 16 cores and 64 GB per trial, and GCE fleet topology.
This is a bug-finding experiment, matching the previous hybrid config.

All ground-truth harnesses and CPVs of the selected benchmarks are included.
The address, memory, and undefined sanitizers are requested, then the runtime
intersects them with each harness's ground-truth sanitizers. Memory is added
to the earlier configuration because this random sample includes a memory
sanitizer CPV; omitting it would silently omit that target.

The frozen selection expands to **171 jobs**: 168 address and 3 memory jobs,
with 72 delta and 99 full jobs. Non-CPV harnesses are skipped. The previous
eight workers provide 112 simultaneous slots, so this run needs more than
one wave; the time limits are per trial. Keep separate experiment/report
directories from the original hybrid experiment and the smoke test.

## Four-task GCE smoke test

Use [gce-sample-hybrid-random-smoke.yaml](../../experiment-configs/icse/gce-sample-hybrid-random-smoke.yaml).
These four explicit smoke selectors exercise the deployment; they are not
the random sample and do not contribute scientific results:

| Stratum | Benchmark | Harness | CPV |
| --- | --- | --- | --- |
| C/C++ delta | `afc-curl-delta-05` | `curl_fuzzer_dict` | `cpv_0` |
| C/C++ full | `atlanta-pcre2-full-01` | `pcre2_fuzzer` | `cpv_0` |
| JVM delta | `afc-apache-commons-compress-delta-02` | `ExpanderFuzzer` | `cpv_0` |
| JVM full | `atlanta-jsoup-full-01` | `HtmlFuzzer` | `cpv_4` |

Each selector uses address sanitizer and one trial, giving exactly **four
jobs**, all using `crs-sample-hybrid`. The smoke has a 10-minute run window,
$2 per-trial LLM budget, a 3-hour build allowance, and a 30-minute verification
allowance. It provisions one 16-vCPU orchestrator, one 64-vCPU worker with four
slots, and one 32-vCPU evaluator with two slots and one concurrent build.
Reaching the time/budget limit is expected; the smoke does not require finding
every target bug. Confirm all four jobs start and finish, the hybrid CRS can
make authenticated LiteLLM requests, and artifacts can be collected.

## Tailscale, LiteLLM, and launch

Both configs use external LiteLLM and forward these operator environment
variables through `cloud.env` to every VM role:

- `CRSBENCH_TAILSCALE_AUTH_KEY`: reusable Tailscale auth key for the fleet.
- `CRSBENCH_LLM_UPSTREAM_BASE_URL`: LiteLLM URL reachable from the tailnet.
  A Tailscale IP avoids dependence on MagicDNS resolution inside CRS containers.
- `CRSBENCH_LLM_UPSTREAM_MASTER_KEY`: LiteLLM master key for budget tracking.
- `HF_TOKEN`: token with access to the benchmark dataset.

Keep these values in the local `.env` or environment. Never put key values in
tracked YAML. Allow the fleet's devices to reach LiteLLM in the tailnet policy.
GCE bootstrap installs Tailscale and joins the tailnet before starting runtime
services. A failed connection stops bootstrap; fix connectivity and retry the
same tasks. See [GCE Tailscale setup](../deployment/gce-cloud-orchestration.md#private-litellm-over-tailscale).

The deploy key and GCP authentication prerequisites are the same as for the
[previous GCE workflow](../deployment/gce-cloud-orchestration.md). Before
launch, make the new suite and bootstrap changes available on the configured
remote `icse` Git ref, or set `cloud.defaults.crsbench_git_ref` to a published
ref containing them. The VMs clone that ref; local uncommitted suite files are
not sufficient.

Run the smoke first:

```bash
CONFIG=experiment-configs/icse/gce-sample-hybrid-random-smoke.yaml
uv run crsbench cloud --config "$CONFIG" preflight --strict
uv run crsbench cloud launch --config "$CONFIG"
uv run crsbench cloud --config "$CONFIG" monitor
uv run crsbench cloud --config "$CONFIG" collect --force
uv run crsbench cloud --config "$CONFIG" teardown --force
```

Then use the same lifecycle with
`CONFIG=experiment-configs/icse/gce-sample-hybrid-random-finding.yaml`.
Collect before teardown, including diagnostics when jobs fail. Live smoke
execution is a separate step from generating and validating these configs.
