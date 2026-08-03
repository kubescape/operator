# Default posture frameworks

## Overview

Install-time `defaultFrameworks` in `clusterData` controls which frameworks the
operator uses when a posture scan does not name targets explicitly.

## Precedence

1. **Explicit request** — `scanV1.targetNames` / API payload with non-blank names
2. **`defaultFrameworks`** — from Helm / `clusterData` (when non-empty)
3. **Legacy fallback**
   - empty `scanV1` / continuous scan → `["all"]`
   - startup scan / exception rescan → `["allcontrols", "nsa", "mitre"]`

Blank entries in `targetNames` (e.g. `[""]`) are treated as absent and fall
through to step 2/3.

## Continuous scanning

Continuous scanning builds requests with no `TargetType` / `TargetNames`. Those
scans intentionally inherit the same defaults as an empty `scanV1`.

## Helm

See the kubescape-operator chart `defaultFrameworks` value. Requires an operator
image that includes this feature.
