#!/usr/bin/env bash
# Drive a ChatAFL fuzzing campaign against the patched Matter all-clusters-app DUT.
#
# Prerequisites (Linux campaign host):
#   1. ChatAFL built with Matter support: `make MATTER=1 clean all`
#      (llvm_mode / afl-clang-fast is NOT required — see note below.)
#   2. The DUT built for Linux with:
#        - matter_fuzz_dut_transport=true   (plaintext accept + session injection
#                                            + --secured-device-port support)
#        - matter_fuzz_afl_instrument=true  (-fsanitize-coverage=trace-pc-guard +
#                                            AFLNet's afl-llvm-rt.o.c runtime +
#                                            deferred forkserver before the event
#                                            loop) so AFLNet gets the SHM coverage
#                                            bitmap AND each run is fast.
#      See ai_docs/benchmark-fuzzers.md for the exact gn args.
#   3. Seeds generated: `python3 gen_matter_seeds.py -o seeds`
#
# Instrumentation note: AFLNet's legacy afl-clang-fast LLVM pass no longer builds
# on modern LLVM. Instead the DUT is instrumented with the SDK's own pigweed
# clang via -fsanitize-coverage=trace-pc-guard, whose callbacks are provided by
# AFLNet's afl-llvm-rt.o.c (built with USE_TRACE_PC). Net result is identical: an
# AFL edge-coverage bitmap + forkserver, with no toolchain swap.
#
# Usage:
#   CHATAFL_DIR=/path/to/ChatAFL DUT=/path/to/chip-all-clusters-app ./run_campaign.sh [out_dir]
#
# Env knobs:
#   PORT=5560   operational UDP port (must avoid a concurrent EP2 run on 5540)
#   SEEDS=seeds seed corpus dir
#   KVS=...     DUT key-value store path (wiped each start)
#   CHATAFL_LLM=1           enable LLM calls; needs CHATAFL_OPENAI_KEY
#   CHATAFL_OPENAI_KEY=sk-… OpenAI key; absent ⇒ catalog-only, offline
#   CHATAFL_OPENAI_BASE=…   custom API base (e.g. Ollama)
#   CHATAFL_OPENAI_MODEL=…  model name for custom base
set -euo pipefail

CHATAFL_DIR="${CHATAFL_DIR:?set CHATAFL_DIR to the ChatAFL checkout}"
DUT="${DUT:?set DUT to the AFL-instrumented all-clusters-app binary}"
OUT="${1:-chatafl-out}"
SEEDS="${SEEDS:-seeds}"
KVS="${KVS:-/tmp/chatafl-matter-kvs}"
PORT="${PORT:-5560}"
# Settle time (usecs) between forking a run's DUT child and sending the request.
# The deferred child resumes straight at the event loop, but still needs to reach
# epoll_wait on the inherited socket before the datagram arrives (AFLNet only
# polls ~1ms for the response after sending). The deferred forkserver is started
# after the event loop prepares fd sets, so 10ms is enough on this DUT. Too small
# ⇒ AFLNet sees an empty response and aborts ("No server states detected"). Raise
# it on a slower / more heavily loaded host.
DELAY="${DELAY:-10000}"

[ -d "$SEEDS" ] || { echo "seed dir '$SEEDS' missing — run gen_matter_seeds.py first"; exit 1; }
rm -f "$KVS"

# ChatAFL binary (built with `make MATTER=1`).
AFL_BIN="$CHATAFL_DIR/afl-fuzz"
[ -x "$AFL_BIN" ] || { echo "ChatAFL binary '$AFL_BIN' not found; build with: make MATTER=1"; exit 1; }
export CHATAFL=1
export CHATAFL_LLM="${CHATAFL_LLM:-0}"
if [ "$CHATAFL_LLM" = "1" ] &&
   [ -z "${CHATAFL_OPENAI_KEY:-}${OPENAI_API_KEY:-}${CHATAFL_OPENAI_BASE:-}" ]; then
  echo "CHATAFL_LLM=1 but no CHATAFL_OPENAI_KEY/OPENAI_API_KEY/"
  echo "CHATAFL_OPENAI_BASE set; the run will proceed catalog-only (offline)."
fi

# AFL host-environment bypasses (the campaign host's core_pattern pipes to an
# external handler and the CPU governor is 'powersave'; neither is fatal here).
export AFL_SKIP_CPUFREQ="${AFL_SKIP_CPUFREQ:-1}"
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES="${AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES:-1}"
export AFL_NO_AFFINITY="${AFL_NO_AFFINITY:-1}"
export AFL_SKIP_CORE_PATTERN="${AFL_SKIP_CORE_PATTERN:-1}"

# Flags:
#   -N udp://127.0.0.1/$PORT  Matter operational UDP port
#   -K                        send SIGTERM to terminate each forked run
#   -D 10000                  10ms settle before sending (deferred forkserver makes
#                             each child ready almost immediately — no re-init)
#   -m none                   no memory limit (large DUT)
#   -t 2000+                  per-run timeout, skip-timeout mode
exec "$AFL_BIN" \
  -d \
  -i "$SEEDS" -o "$OUT" \
  -N "udp://127.0.0.1/$PORT" \
  -P MATTER -E -K \
  -D "$DELAY" \
  -m none -t 4000+ \
  -- "$DUT" --secured-device-port "$PORT" --KVS "$KVS"
