# efi-vuln benchmark

The evaluation benchmark used in the paper is released as its own public repository:

  **https://github.com/20000419/efi-vuln**

Contents: 300 function-level C snippets forming **150 patch-verified vulnerability
pairs** (150 vulnerable + 150 corresponding post-patch functions), drawn from three
public disclosure lines:

| Source | Pairs |
|---|---|
| Binarly Research Team advisories (BRLY-*) | 116 |
| LogoFAIL image-parser set (BRLY-LOGOFAIL-*) | 24 |
| Damn Vulnerable UEFI educational series (BRLY-DVA-*) | 10 |
| **Total** | **150** |

Each sample directory (`<ID>` for vulnerable, `<ID>-fixed` for patched) contains
`src.c` and `meta_data.json` with the CWE annotation and provenance to the public
advisory. See `sample_index.csv` and `dataset_statistics.md` in that repository.

Every sample derives from a publicly disclosed advisory with a vendor-committed
patch. Do NOT add raw vendor firmware images or full decompilation output here —
redistributing proprietary firmware is out of scope for this release.
