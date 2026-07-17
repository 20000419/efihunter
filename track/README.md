# Track phase (optional symbolic-validation filter)

The Track phase builds a Vulnerability Call Flow Graph (VCFG) and uses symbolic
execution to validate high-confidence Analyze-phase flags. It is an OPTIONAL
deployment-time precision filter, not part of the detection signal reported in the
paper's tables. The reference implementation is a stub/partial; a full release is
planned. Analyze-phase output is fully reproducible from the scripts in ../analyze.
