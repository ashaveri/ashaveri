#!/bin/sh
# Weights arrive on a mount the gateway does not control. Checking the manifest against
# the files before the first receipt is signed means a swapped model produces a loud
# startup failure instead of a verifiable receipt for the wrong weights.
#
# The gateway compares this manifest with --weights-manifest and refuses a run where the
# two names are not one file, so a value set without its partner is refused here rather
# than reaching a process that would sign a digest nothing checked.
if [ -n "${ASHAVERI_WEIGHTS_DIR}" ] && [ -z "${ASHAVERI_WEIGHTS_MANIFEST}" ]; then
  printf 'signerd: %s\n' "ASHAVERI_WEIGHTS_DIR names ${ASHAVERI_WEIGHTS_DIR} and ASHAVERI_WEIGHTS_MANIFEST is empty, so this deployment sets one weights input without the other and a receipt would carry a digest its boot check never verified" >&2
  exit 1
fi
if [ -z "${ASHAVERI_WEIGHTS_DIR}" ] && [ -n "${ASHAVERI_WEIGHTS_MANIFEST}" ]; then
  printf 'signerd: %s\n' "ASHAVERI_WEIGHTS_MANIFEST names ${ASHAVERI_WEIGHTS_MANIFEST} and ASHAVERI_WEIGHTS_DIR is empty, so this deployment sets one weights input without the other and a receipt would carry a digest its boot check never verified" >&2
  exit 1
fi
if [ -n "${ASHAVERI_WEIGHTS_DIR}" ] && [ -n "${ASHAVERI_WEIGHTS_MANIFEST}" ]; then
  node /app/weights.mjs verify "${ASHAVERI_WEIGHTS_DIR}" "${ASHAVERI_WEIGHTS_MANIFEST}" || exit 1
fi

exec node /app/dist/cli.js "$@"
