# Track phase (optional symbolic-validation filter)

Track is a proposed validation stage: construct a Vulnerability Call Flow Graph
(VCFG) and use symbolic execution to check candidate findings. This directory
contains design notes, not an automated symbolic filter. Historical predictions
were not filtered by this stage. The case studies used manual validation.

Fixed-output metric recomputation is documented in
[CSCloud experiment provenance](../docs/CSCloud2026.md). It is separate from
replaying the historical inference process with complete original settings.
