# 3FA desktop: SOPS lifecycle plus an allowlisted public-config build boundary.
set shell := ["bash", "-euo", "pipefail", "-c"]
set dotenv-load := false

_default:
    @just --list --unsorted

use name:
    @ores-sops use {{ name }}

status:
    @ores-sops status

edit name:
    @ores-sops edit {{ name }}

encrypt name:
    @ores-sops encrypt {{ name }}

diff name:
    @ores-sops diff {{ name }}

refresh:
    @ores-sops refresh

lock:
    @ores-sops lock

verify:
    @ores-sops verify

verify-release-policy name="prod":
    @python3 scripts/verify-sops-release-policy.py .sops.yaml {{ name }}

formal:
    python3 formal/session_model.py
    python3 formal/app_lifecycle_model.py

# Desktop client values are compiled with option_env!, so the launcher accepts
# only the reviewed public allowlist before invoking Cargo.
run name="dev":
    sops exec-file --input-type dotenv --output-type json env/enc/{{ name }}.env.enc 'python3 scripts/build-with-public-env.py {} -- cargo run'

build-release name="prod":
    python3 scripts/verify-sops-release-policy.py .sops.yaml {{ name }}
    sops exec-file --input-type dotenv --output-type json env/enc/{{ name }}.env.enc 'python3 scripts/build-with-public-env.py {} --require-configured -- cargo build --release'
