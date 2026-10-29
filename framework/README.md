# CRSBench experiment wrapper

`framework/` is a local usability wrapper around CRSBench. It selects benchmarks,
models, and CRSs; renders a standard experiment; prepares local Valkey; checks the
LLM endpoint; and launches the native CRSBench evaluator, worker, and runner in
tmux. CRSBench remains responsible for execution, queues, evaluation, reports, and
trial artifacts.

The wrapper assumes one local experiment at a time.

## Configuration

`framework/cfg.json` contains only run-specific selections:

```json
{
  "llm_host": "http://127.0.0.1:4000",
  "models": ["claude-opus-4-8"],
  "crses": ["discver", "crs-bug-finding-claude-code"],
  "benchmarks": ["sanity-mock-c-delta-01"],
  "storage": "results"
}
```

Stable settings such as timeouts, worker sizing, evaluator sizing, task, and mode
live in `framework/experiment-template.yaml`.

CRS-specific environment variables live in `framework/cfg_crs_env.yaml`. Every
selected CRS is expanded across every selected model. Supported placeholders are
`{model}`, `{llm_host}`, and `{repo_root}`. To add another CRS, add its canonical
registry entry, add an `additional_env` mapping, and select its name in `cfg.json`.

## Run

From the repository root:

```bash
uv run python framework/run.py --config framework/cfg.json --dry-run
uv run python framework/run.py --config framework/cfg.json
```

A dry run renders and validates all generated files and checks Caddy/models, but
does not stop workers, modify Valkey, create a durable archive, or launch tmux.

For a fresh run, the wrapper validates the configuration first, stops stale local
CRSBench workers, restarts the repository-owned loopback Valkey, flushes its
database, requires `PONG`, checks Caddy/models, archives the configuration, and
launches CRSBench. Valkey remains running afterward.

Destructive Valkey management is refused unless `runtime.redis_host` in the
template resolves to `localhost:6379` or `127.0.0.1:6379`. Remote and shared
services are never restarted or flushed.

## Logs and results

Each run archive is stored at:

```text
<storage>/framework-runs/<timestamp>/
├── experiment.yaml
├── runner.exit
├── logs/
│   ├── evaluator.log
│   ├── worker.log
│   └── run.log
├── csv/
│   ├── <experiment-name>_trial_metrics.csv
│   └── <experiment-name>_benchmark_summary.csv
└── support/
    ├── benchmark-suite.yaml
    ├── framework.json
    └── registry/
```

The two CSVs are convenience views generated from CRSBench trial artifacts. CSV
errors are logged but do not replace CRSBench's runner exit status.

CRSBench saves compose logs and registered CRS log directories in each trial:

```text
<storage>/experiment-data/<experiment-name>/.../trial-*/output/logs/crs/
└── <generated-crs-name>/log_dir/
```

The foreground wrapper prints exact `tmux attach` and `tail -f` commands while a
run is active.

## Retry

Retry an archived experiment with:

```bash
uv run python framework/run.py \
  --config framework/cfg.json \
  --retry <storage>/framework-runs/<timestamp>/experiment.yaml
```

Retry mode restores archived suite and registry support files, stops stale local
workers, performs a non-destructive Valkey connectivity check, checks Caddy, and
runs CRSBench with `--queue-mode continue --retry-failed`. It never restarts or
flushes Valkey. Retry CSVs are written beneath that retry's archive directory.

## Reparse existing results

```bash
uv run python -m framework.results \
  <storage>/experiment-data/run-YYYYMMDD-HHMMSS \
  --benchmarks-dir benchmarks \
  --output-dir <storage>/framework-runs/YYYYMMDD-HHMMSS/csv
```

## Cleanup behavior

The wrapper removes only transient files it generated for the current invocation:

- `benchmark-suites/custom/<run-id>.yaml`
- `oss-crs/registry/<crs>-<model>.yaml`
- `experiment-<run-id>.yaml`

Archived configuration, tmux logs, CSVs, and CRSBench artifacts remain durable.
