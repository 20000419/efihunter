# Changes

## cscloud2026-revision-20261014.1

- Make long-term context traversal terminate on cycles and avoid recursion-depth
  failures; retain one representative path per function.
- Read a common earlier-batch memory snapshot for all functions in a batch.
- Add offline graph tests and checks of the archived headline metrics.
- Add the verified 1,500-record headline export, source hash, and standard-library
  scoring/export script. Preserve existing prediction files.
- Align the README with full-rule injection and historical evidence boundaries.
- Record CSCloud 2026 acceptance and the merged EDK2 correction.

The code correction does not regenerate or overwrite historical model outputs.
