#!/bin/sh
# Weights arrive on a mount the gateway does not control. Checking the manifest against
# the files before the first receipt is signed means a swapped model produces a loud
# startup failure instead of a verifiable receipt for the wrong weights.
if [ -n "${ASHAVERI_WEIGHTS_DIR}" ] && [ -n "${ASHAVERI_WEIGHTS_MANIFEST}" ]; then
  node /app/weights.mjs verify "${ASHAVERI_WEIGHTS_DIR}" "${ASHAVERI_WEIGHTS_MANIFEST}" || exit 1
fi

exec node /app/dist/cli.js "$@"
