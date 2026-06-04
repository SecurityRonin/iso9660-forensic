# Reference Specifications — Provenance Manifest

This directory holds authoritative specification documents and reference test
media consulted while building `iso9660-forensic`. **The documents themselves are
deliberately NOT committed** — they are gitignored. Only this manifest is
tracked, recording for each item: title, issuing body, the exact source URL, the
date fetched, a SHA-256 checksum, and its copyright / redistribution status.

## Why cite-don't-commit

Finding a copy on a public website does **not** grant a licence to redistribute
it. Copyright persists regardless of where a copy is hosted, and committing a PDF
to this repository would be *republication* — a separate, higher-risk act than
holding one reference copy locally. Copyright also protects only the *expression*
in these documents, never the facts (byte layouts, algorithms), so the project
can implement every format and describe the structures in its own words
(`docs/FORMATS.md`, code comments) without shipping the PDFs. This manifest gives
full, auditable provenance — anyone can re-fetch each file and verify the bytes
against the recorded SHA-256 — without redistributing copyrighted material.

> Not legal advice. For a commercial product, confirm redistribution terms with
> IP counsel before committing any of these files.

## How to obtain the files

Re-download each item from its URL below and drop it in this directory, then
verify: `shasum -a 256 -c specs/SHA256SUMS` (or check individual hashes here).
Generated test media is reproduced by `corpus/gen_udf_type2.sh`.

## Manifest

### Filesystem / sector specifications

| File | Document | Body | Source URL | Fetched | SHA-256 | Redistribution |
|---|---|---|---|---|---|---|
| `ECMA-119_4th_edition_june_2019.pdf` | ECMA-119 (ISO 9660) 4th ed. | Ecma International | https://www.ecma-international.org/wp-content/uploads/ECMA-119_4th_edition_june_2019.pdf | 2026-06-03 | `b0babe7d…04be`† | **Permitted** under Ecma copyright policy (retain notice); verify Clause 4 |
| `ECMA-167_3rd_edition_june_1997.pdf` | ECMA-167 (UDF base) = ISO/IEC 13346 | Ecma International | https://www.ecma-international.org/wp-content/uploads/ECMA-167_3rd_edition_june_1997.pdf | 2026-06-03 | `6efe0f59…34b7` | **Permitted** (Ecma policy) |
| `ECMA-130_2nd_edition_june_1996.pdf` | ECMA-130 (CD-ROM sectors + subchannel Q) | Ecma International | https://www.ecma-international.org/wp-content/uploads/ECMA-130_2nd_edition_june_1996.pdf | 2026-06-03 | `576fb91e…f7b8` | **Permitted** (Ecma policy) — legal substitute for Red Book |
| `rrip112.pdf` | Rock Ridge RRIP, IEEE P1282 draft 1.12 | IEEE | https://people.freebsd.org/~emaste/rrip112.pdf | 2026-06-03 | `4af95880…9ad6` | Cite only (IEEE draft) |
| `boot-cdrom.pdf` | El Torito Bootable CD-ROM v1.0 (1995) | Phoenix / IBM | https://pdos.csail.mit.edu/6.828/2014/readings/boot-cdrom.pdf | 2026-06-03 | `a906b6fa…04be` | Cite only |
| `udf201.pdf` | OSTA UDF 2.01 | OSTA | http://13thmonkey.org/documentation/UDF/udf201.pdf | 2026-06-03 | `83f12674…25c9` | Cite only (OSTA; verify) |
| `udf260.pdf` | OSTA UDF 2.60 | OSTA | http://www.13thmonkey.org/documentation/UDF/udf260.pdf | 2026-06-03 | `e338ef7f…e71b` | Cite only (OSTA; verify) |
| `joliet-spec.html` | Joliet Specification | Microsoft | https://pismotec.com/cfs/jolspec.html | 2026-06-03 | `0e4e875c…35a3` | Cite only (Microsoft) |

### Audio-CD specifications

| File | Document | Body | Source URL | Fetched | SHA-256 | Redistribution |
|---|---|---|---|---|---|---|
| `mmc3r10g.pdf` | SCSI MMC-3 r10g (T10/1363-D) — **CD-Text in Annex J** | INCITS / T10 | http://www.13thmonkey.org/documentation/SCSI/mmc3r10g.pdf | 2026-06-04 | `6f08e220…40c0` | Cite only (INCITS draft: member-reproduction only) |
| `iec60908_redbook.pdf` | IEC 60908:1999 (Red Book / CD-DA) — 216-pp scan | IEC / Philips / Sony | https://raw.githubusercontent.com/suvozy/CD-Copy-protect/master/IEC%2060908-1999(ed2.0)%5BBR,EN+FR%5D%5BRed%20Book%5D%5BCD-DA%5D/IEC_60908_1999_International_Standard.pdf | 2026-06-04 | `c42284cc…e70c` | **DO NOT redistribute** (copyrighted; scanned leak). Use ECMA-130 instead |
| `mb_discid.html` | MusicBrainz Disc ID Calculation | MetaBrainz | https://musicbrainz.org/doc/Disc_ID_Calculation | 2026-06-03 | `af25b846…e51a` | Permitted under CC BY-NC-SA (attribute) |
| `cddb.html` | CDDB / freedb disc-ID background | Wikipedia | https://en.wikipedia.org/wiki/CDDB | 2026-06-04 | `b0258928…8f9c` | Permitted under CC BY-SA (attribute) |

### Reference implementations (consulted, not stored)

- GNU **libcdio** "CD Text Format" — https://www.gnu.org/software/libcdio/cd-text-format.html (GFDL)
- **Unofficial CD-Text FAQ** — http://web.ncf.ca/aa571/cdtext.htm
- **libyal libodraw** raw optical-disc format notes — https://github.com/libyal/libodraw
- **sacd-ripper** ScarletBook wiki (reverse-engineered SACD) — https://github.com/sacd-ripper/sacd-ripper/wiki/ScarletBook

### Located but not obtained here

- **Scarlet Book (SACD System Description, Parts 1–3)** — https://archive.org/details/super-audio-cd-system-description (archive.org is firewalled from the build sandbox; fetch directly). Philips/Sony proprietary — **do not redistribute**.

### Generated test media (reproducible, not downloaded)

| File | How produced | SHA-256 |
|---|---|---|
| `udf_vat.img` | `mkudffs --media-type=cdr --udfrev=1.50` (real UDF Virtual/VAT partition) — see `corpus/gen_udf_type2.sh` | `195a192e…a778` |
| `udf_spar.img` | `mkudffs --media-type=dvdrw --udfrev=2.01` (real UDF Sparable partition) | `09227893…25c9` |

These are output of the GPL `udftools` `mkudffs`; the bytes are freshly-generated
test data (no third-party copyright) and are regenerable from the script above.

---

## Full SHA-256 digests (verification source of truth)

Truncated digests above are for readability; verify against the complete values
below (`cd specs && shasum -a 256 -c` against this block, or recompute):

```
a906b6fa2de740354ab15b4295b57f95caa330c0c7374a2740b388788d7b04be  boot-cdrom.pdf
b025892897017e8580a67b5a282c94acbe621781f9513e81cd65be2fb8fc8f9c  cddb.html
b0babe7d869b0ca3e42bc1c8eb1c72de38ec7386dc257fc97addaaea3cc30d23  ECMA-119_4th_edition_june_2019.pdf
576fb91e38e850b7597767ea48402a33e79a89ae4f7d41290e884142ad47f7b8  ECMA-130_2nd_edition_june_1996.pdf
6efe0f591e21da2b17288076b2653dc616800bdc94f83e74acba9279c84c34b7  ECMA-167_3rd_edition_june_1997.pdf
c42284cc3945ee3e79fd4d20aacf3809f6a0b97e618d14e7a8339bf7d1dae70c  iec60908_redbook.pdf
0e4e875c23ee0380b2b5a8508a483bea71919a148055d7aa4894fa307c2935a3  joliet-spec.html
af25b8462ed8170efabea2d266f0b4bf9d96f304b538f802924b6ea09d2fe51a  mb_discid.html
6f08e220ed5f418d5cd9bb205077b8e0bebe97c683dc62bc59954c5211d840c0  mmc3r10g.pdf
4af958809aecc938ae0d4ac51c1afdb6ac4b6c9359b6bb207acae88c58a29ad6  rrip112.pdf
83f1267466928782cd239ed39cbc1acd384ddf799900213d75d74e97f9f10f53  udf201.pdf
e338ef7f06cb4c8ef9511fef337b3b12bf3ba29a3a2de85ae84dfd316f5ae71b  udf260.pdf
195a192ec6f0b3bd592336e9f24c6c02f0fda49c994ded3888051d428eaca778  udf_vat.img
09227893bdb171f3d58860ac2e4db81f8856692f38ded7080e02b21e2f2d25c9  udf_spar.img
```
