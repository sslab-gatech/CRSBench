# ICSE Hybrid CRS Random-Sample Evaluation

This ICSE experiment samples whole benchmark IDs from `crsbench/all` to
evaluate hybrid CRS across both language groups and both modes. The draw is
independent of standalone experiment outcomes.

## Sampling protocol

The frozen population contains 124 non-sanity benchmarks. The original draw has no exclusions.
The comparison retains 26 benchmarks after removing two previously excluded
standalone targets, without replacement or redraw. Language comes from `project.yaml`, with C/C++ grouped
as `c` and JVM/Java as `jvm`. Mode follows the experiment runtime's `auto`
policy: delta when `delta_mode` is available, otherwise full. Benchmarks
supporting both modes therefore belong to the delta stratum, rather than
appearing twice in the population.

| Stratum | Population | Selected benchmarks |
| --- | ---: | ---: |
| C/C++ delta | 46 | 8 |
| C/C++ full | 17 | 4 |
| JVM delta | 41 | 9 |
| JVM full | 20 | 5 |
| Total | 124 | 26 |

The experiment draws 28 benchmarks using the largest remainder method. Take
the floor of `28 * stratum_size / 124`, then distribute remaining slots to
the largest fractional remainders. Equal remainders follow the stratum order
shown above. The original draw yields 10/4/9/5, and post-draw exclusions
yield 8/4/9/5. The command fails if the requested sample is too small to
represent all four groups.

Report per-stratum results. For population-wide benchmark averages, weight
stratum averages by their population shares; integer rounding means sample
shares are not exactly the population shares. Benchmark IDs are the sampling
units, so projects with multiple benchmark IDs can appear more than once.

Reproduce the frozen selection from the repository root:

```bash
uv run crsbench benchmark sample \
  --source-suite benchmark-suites/crsbench/all.yaml \
  --benchmarks-root benchmarks \
  --seed 20261104 \
  --size 28 \
  --exclude afc-curl-delta-01 \
  --exclude atlanta-libxml2-delta-01 \
  --name icse/hybrid-random \
  --release-date 11.04.2026 \
  --output benchmark-suites/icse/hybrid-random.yaml \
  --manifest experiment-configs/icse/hybrid-random-sampling.json
```

The command samples without replacement from sorted IDs in the fixed order
`c/delta`, `c/full`, `jvm/delta`, `jvm/full`, using Python 3.12
`random.Random(seed).sample`. It writes a runnable suite and a JSON audit
manifest containing every population ID, selections, seed, stratum sizes,
allocation rule, and SHA-256 fingerprints of the source suite and metadata.
`--size` uses proportional allocation; `--per-stratum` remains an alternative
for explicitly balanced samples, and the options are mutually exclusive.
Existing outputs
are protected; use alternate output paths to verify reproduction, or
`--force` to intentionally replace them. Missing/invalid metadata,
unsupported languages, filtered source-suite selectors, and insufficient
stratum sizes fail the command rather than silently changing eligibility.

The frozen suite is [hybrid-random.yaml](../../benchmark-suites/icse/hybrid-random.yaml);
the audit record is [hybrid-random-sampling.json](../../experiment-configs/icse/hybrid-random-sampling.json).
Do not redraw after inspecting performance. Record infrastructure failures
and retry the same selected tasks; do not replace them with easier targets.
The original draw includes two previously excluded RQ1 targets,
`afc-curl-delta-01` and `atlanta-libxml2-delta-01`.
The comparison excludes them because standalone results are unavailable.
The repeatable `--exclude` option removes these IDs after the original draw;
it does not redraw or fill their slots. The manifest preserves the original
selection, the exclusions, and the retained selection. Historical execution
batches and raw results remain unchanged. The retained suite has 26 benchmarks
across all four strata and 98 CPVs.

## Main experiment

Use [gce-sample-hybrid-random-finding.yaml](../../experiment-configs/icse/gce-sample-hybrid-random-finding.yaml).
It uses the LiteLLM model name `claude-opus-4-6_jiho` for Opus 4.6 and
preserves the earlier ICSE hybrid configuration's three trials, 8-hour
finding window, $30 per-trial LLM budget, seed input, 16 cores and 64 GB
per trial, and GCE fleet topology.
This is a bug-finding experiment, matching the previous hybrid config.

All ground-truth harnesses and CPVs of the selected benchmarks are included.
The runtime intersects the configured sanitizers (address, memory, and
undefined) with each harness's ground-truth sanitizers.

The frozen selection expands to **129 address-sanitizer jobs** across 84 delta
and 45 full jobs. The run skips harnesses without CPVs. The eight workers
provide 112 simultaneous slots, so the run needs more than one wave. The time
limits are per trial. Keep separate experiment/report
directories from the original hybrid experiment and the smoke test.

The evaluation compares fuzzer-only, agent-only, and hybrid results on the
same random sample. This YAML runs the hybrid arm. Reuse standalone results
only where versions, inputs, budgets, trial counts, harnesses, and sanitizers
match; obtain any missing baseline results on these same selected targets.

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

Set these in the repository-root `.env`, replacing the placeholders:

```dotenv
CRSBENCH_TAILSCALE_AUTH_KEY=YOUR_REUSABLE_TAILSCALE_AUTH_KEY
CRSBENCH_LLM_UPSTREAM_BASE_URL=http://YOUR_LITELLM_TAILSCALE_IP:4000
CRSBENCH_LLM_UPSTREAM_MASTER_KEY=YOUR_LITELLM_MASTER_KEY
HF_TOKEN=YOUR_HUGGINGFACE_TOKEN
```

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
gcloud auth login
gcloud auth application-default login

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
The sample is already saved in the suite: launching or retrying does not
run the sampler again. To verify reproduction without replacing it, use the
sampling command with output paths under `/tmp`; `--force` is only needed
when intentionally replacing existing sampling outputs.
