# Optical Disc Data Formats — Landscape & Gap Analysis

A survey of the optical-disc **data/logical** format universe (not physical
manufacturing) that a forensic disc-image parser must handle, mapped against
what `iso9660-forensic` **v0.3.0** supports today.

Research method: a fan-out web survey with adversarial verification (107 agents,
25 sources fetched, 113 claims extracted, 24 confirmed by unanimous 3-vote,
1 refuted). The **filesystem and spec-citation layers are spec-verified**; the
**sector / application / container / Apple layers** rest on domain knowledge plus
uncited (but reputable) sources and are flagged accordingly.

> **Status update (unreleased, on `main` since v0.2.0).** Implemented since the
> survey: SUSP `ER`, Rock Ridge `PN`/`SF` (rock_ridge); CD sector **Mode 2
> Form 1 / 2336 / 2448** layouts (sector); a **BIN/CUE sheet parser** (cue).
> El Torito `0xEF` (EFI) was already supported. These rows are marked
> **✅ (v0.3-dev)** below.

## Confidence legend

| Mark | Meaning |
|---|---|
| ✅ **Verified** | Confirmed verbatim against a primary spec (unanimous adversarial vote) |
| 🟡 **Domain** | Reputable source(s) fetched but not adversarially verified; treat as solid but not spec-quoted |
| ⚠️ **Uncertain** | Rests on general knowledge; primary source still to be obtained |

---

## 1. Layered taxonomy

Optical formats stack into five layers. `iso9660-forensic` lives almost entirely
in the **sector** and **filesystem + extensions** layers.

```
Layer 5  CONTAINER     how the sector stream is stored as a file (.iso, BIN/CUE, NRG, E01…)
Layer 4  APPLICATION   structures built on files (DVD-Video VIDEO_TS, Blu-ray BDMV, VCD…)
Layer 3  EXTENSIONS    Rock Ridge, Joliet, El Torito, Apple — bolted onto ISO 9660
Layer 2  FILESYSTEM    ISO 9660 / ECMA-119  •  UDF / ECMA-167
Layer 1  SECTOR        how bytes are framed on the medium (Mode 1/2, raw 2352, subchannel)
```

A key simplification: **physical write variants** (CD-R/RW, DVD±R/RW, DVD-RAM,
DL, BD-R/RE, BDXL, HD DVD) almost never change the logical data format. The one
real exception is **packet-written / incrementally-recorded UDF**, which uses a
**Virtual Allocation Table (VAT)** or **Pseudo-OverWrite (POW)** to remap blocks
— without that logic a parser silently misses files on those discs. ✅

---

## 2. Authoritative specifications

| Format | Body / Doc | Download | Conf. |
|---|---|---|---|
| ISO 9660 | ECMA-119, 4th ed. (Jun 2019) | https://www.ecma-international.org/wp-content/uploads/ECMA-119_4th_edition_june_2019.pdf | ✅ |
| SUSP (System Use Sharing Protocol) | IEEE P1281 (referenced by P1282; no stable standalone URL verified) | *open item* | ✅ (existence) |
| Rock Ridge RRIP | IEEE P1282, Draft 1.12 | https://people.freebsd.org/~emaste/rrip112.pdf | ✅ |
| Joliet | Microsoft Joliet Spec | https://pismotec.com/cfs/jolspec.html · https://nick-black.com/dankwiki/images/7/73/Microsoft_Joliet_Spec.pdf | ✅ |
| El Torito | Phoenix/IBM v1.0 (1995) | https://pdos.csail.mit.edu/6.828/2014/readings/boot-cdrom.pdf | ✅ |
| UDF base | ECMA-167, 3rd ed. (Jun 1997) = ISO/IEC 13346 | https://www.ecma-international.org/wp-content/uploads/ECMA-167_3rd_edition_june_1997.pdf | ✅ |
| UDF 2.01 | OSTA UDF 2.01 (Mar 2000) | http://13thmonkey.org/documentation/UDF/udf201.pdf | ✅ |
| UDF 2.60 | OSTA UDF 2.60 (Mar 2005) | http://www.13thmonkey.org/documentation/UDF/udf260.pdf | ✅ |
| CD sector layout | ECMA-130, 2nd ed. (Jun 1996) "CD-ROM" (Yellow Book equiv.) | https://www.ecma-international.org/wp-content/uploads/ECMA-130_2nd_edition_june_1996.pdf | 🟡 |
| Raw optical layout | libyal `libodraw` format notes | https://github.com/libyal/libodraw/blob/main/documentation/Optical%20disc%20RAW%20format.asciidoc | 🟡 |
| CD subchannel | Wikipedia "Compact Disc subcode" | https://en.wikipedia.org/wiki/Compact_Disc_subcode | 🟡 |
| NRG (Nero) | Archive Team file-format wiki | http://fileformats.archiveteam.org/wiki/NRG | 🟡 |
| CCD (CloneCD) | Wikipedia "CloneCD Control File" | https://en.wikipedia.org/wiki/CloneCD_Control_File | 🟡 |
| DVD-Video IFO | Inside DVD-Video / IFO Files | https://en.wikibooks.org/wiki/Inside_DVD-Video/IFO_Files | 🟡 |
| Reference impls | libcdio · libmirage · libbluray · libewf | https://github.com/libcdio/libcdio · https://www.videolan.org/developers/libbluray.html | 🟡 |
| Apple HFS+ / hybrid | Apple TN1150 + AA/BA SUSP entries | *open item* | ⚠️ |

UDF 1.02 / 1.50 / 2.50 PDFs were **not** independently verified in this pass
(only 2.00/2.01/2.60 were); they live in the same `13thmonkey.org/documentation/UDF/`
archive and should be fetched before implementing those revisions.

---

## 3. Gap matrix vs `iso9660-forensic` v0.3.0

Status: **✅ Supported**, **🟨 Partial**, **❌ Not supported**.

### Layer 1 — Sector framing

| Format | Status | Notes |
|---|---|---|
| Mode 1, 2048-byte user data | ✅ | `SectorMode::Iso2048` |
| Raw 2352 (Mode 1 framed) | ✅ | `SectorMode::Raw2352`, data at +16 |
| Mode 2 Form 1, CD-ROM XA (data @24) | ✅ (v0.3-dev) | `SectorMode::Raw2352Mode2`; Form 2 (2324 user bytes) still ❌ |
| 2336 (Mode 2 raw user area) | ✅ (v0.3-dev) | `SectorMode::Mode2_2336`, data @8 |
| 2448 (2352 + 96 subchannel) | ✅ (v0.3-dev) | `Raw2448`/`Raw2448Mode2`; subchannel *bytes* not yet decoded (CD-Text) |

### Layer 2 — Filesystem

| Format | Status | Notes |
|---|---|---|
| ISO 9660 PVD / SVD / dir records / path tables (L+M) / multi-extent | ✅ | three interchange levels; VD types 0/1/2/3/255 ✅ |
| ISO 9660 Enhanced VD (EVD) | ✅ | type code **2** with version byte (BP 7) = 2; distinguished from a Joliet SVD (no UCS-2 escape) via `has_enhanced_volume_descriptor()`, reported in `IsoAnalysis` as "ISO 9660:1999". Validated against a real `xorriso -iso-level 4` image ✅ |
| ISO 9660 Volume Partition Descriptor (VPD, type 3) | ❌ | rare on real media; low priority ✅ |

### Layer 3 — Extensions

| Format | Status | Notes |
|---|---|---|
| SUSP container: `SP`, `CE` | ✅ | the load-bearing traversal entries ✅ |
| SUSP `ER` (Extensions Reference) | ✅ (v0.3-dev) | `rock_ridge::extensions_reference` — id/descriptor/source/version |
| SUSP `ST` / `PD` / `ES` | ❌ | low forensic value ✅ |
| Rock Ridge `NM PX TF SL CL PL RE` | ✅ | 7 of 9 RRIP-1.12 entries ✅ |
| Rock Ridge `PN` (device nodes) | ✅ (v0.3-dev) | `rock_ridge::posix_device` |
| Rock Ridge `SF` (sparse files) | ✅ (v0.3-dev) | `rock_ridge::sparse_file` (metadata only; no index-block reconstruction) |
| Rock Ridge `RR` | n/a | **obsolete** — removed in RRIP 1.12 (existed in 1.10); correctly unsupported ✅ |
| Joliet (UCS-2 BE, 3 escape sequences `25 2F 40/43/45`, 128-byte names, deep hierarchy) | ✅ | verify all three escape levels are read ✅ |
| El Torito (BRVD @ sector 17, catalog ptr @ 0x47, 20-byte entries, platform IDs 0/1/2, media bits 0–3, `0x88` bootable) | ✅ | ✅ |
| El Torito UEFI platform ID `0xEF` | ✅ | already supported — `BootPlatform::EFI` |
| Apple ISO 9660 extensions (`AA`/`BA` SUSP entries) | ❌ | resource forks, Finder type/creator + timestamps ⚠️ |

### Layer 4 — Application structures

All ❌ (the tool sees these as ordinary files/dirs, which remain recoverable). 🟡

| Format | Forensic priority | Notes |
|---|---|---|
| DVD-Video (VIDEO_TS, IFO/VOB) | medium | title/chapter structure can matter in content cases |
| Blu-ray BDMV | low–medium | spec licensed via BDA |
| DVD-Audio | low | |
| Video CD / SVCD (MPEGAV) | low | rides on Mode 2/XA sectors |
| CD-i | low | Mode 2 |
| Photo CD | low | Mode 2 |
| CD-Text | medium | lives in subchannel; needs 2448 sector support |
| Mixed-mode / CD Extra (Blue Book) | low | |

### Layer 5 — Image containers

| Format | Status | Forensic priority | Notes |
|---|---|---|---|
| raw `.iso` (+ raw 2352 / 2336 / 2448) | ✅ | — | current input; sector autodetect |
| BIN/CUE | ✅ (v0.3) | **high** | `cue` module parses the sheet; `open()` resolves `.cue`→`.bin` and windows the data track |
| CCD/IMG/SUB (CloneCD) | ✅ (v0.3) | medium | `ccd` TOC + `[CDText]` parser; `.sub` subchannel via `subq::summarize_sub`; `open()` resolves `.ccd`→`.img`. **Validated against a real CloneCD control file** ✅ |
| NRG (Nero) | ✅ (v0.3) | medium | `nrg` module parses footer (NER5/NERO) + DAOX/DAOI/ETN2/ETNF; `open()` windows the data track via `OffsetReader`. **Validated against real Nero images** (test.nrg data track, p1.nrg audio) ✅ |
| MDF/MDS (Alcohol 120%) | ✅ (v0.3) | medium | `mds` descriptor parser; `open()` windows the `.mdf` data track via `OffsetReader`. **Validated against a real Alcohol MDS** (Aaru-generated from our own ISO) ✅ — which corrected the `TrackMode` mapping to the real `0xA9`–`0xED` range (Mode 1 = `0xAA`). Aaru *and* libmirage independently decode this identically (libmirage matches `mode & 0x0F` against `n` or `n+8`), so the low-3-bits fallback stays faithful; the earlier exact-`0x00`–`0x07` match had mislabeled Mode 1 as Mode 2 |
| CDI (DiscJuggler) | ✅ (v0.3) | low | `cdi::detect` (footer) **plus `cdi::tracks` track-table decode** (kind / start / length / sector sizes); malformed descriptors fall back to detection-only. Layout + `trackMode`/`readMode` map ported from Aaru `DiscJuggler/Read.cs` and **cross-validated byte-exact against 3 real Dreamcast `.cdi` images** via `aaru image info` (Audio + Mode2 readMode 1/2 paths) ✅ |
| CDRDAO TOC/BIN | ✅ (v0.3) | low | `toc` module parses the `.toc` (disc type, `TRACK` modes, `DATAFILE`/`AUDIOFILE` offset + length); `open()` windows the data file via `OffsetReader`. **Validated against a real Aaru-generated TOC** (from our own ISO) — single `MODE1_RAW` track, 188 sectors, offset 0, with an end-to-end read round-trip ✅ |
| B5T/B6T (BlindWrite) | 🟨 (v0.3) | low | `bw5::detect` identifies the TOC by its `"BWT5 STREAM SIGN"` header + `"BWT5 STREAM FOOT"` footer (min 276 B), exposed via `bw5::detect`. Signature confirmed by **six** independent references (Aaru, libmirage `image-b6t`, disc-xplorer, ImHex pattern, 010 template). **Track decode deferred** — no public `.b5t` sample exists to validate against and Aaru/libmirage are read-only (can't self-generate), so a decoder would violate doer-checker. Decode path is ready to port from Aaru `BlindWrite5/Read.cs` once a real sample is sourced |
| DAA (PowerISO) | ❌ | low | Direct-Access-Archive: a compressed (deflate/LZMA) optical-image container, optionally encrypted. An optical image container (fits scope), reverse-engineered (`daa2iso` reference) — the unencrypted variant is decodable. Needs a real sample to validate (doer-checker) |
| Other optical containers (long tail) | ❌ | low | Optical image formats not yet read: CIF (Creator), FCD, GCD/GI (Prassi), P01 (Toast), C2D (WinOnCD), CU2 (PSX), CD (CD-i OptImage), PXI (PlexTools), VC4/000 (Virtual CD). Each needs a real sample to validate (doer-checker), same gate as B5T |

---

## 4. Prioritized roadmap (by forensic value ÷ effort)

Scope note: this crate reads **ISO 9660** and its on-disc extensions, plus the
optical-media layers (sectors, CD-DA subchannel) and optical image containers.
Other filesystems/partition schemes (UDF, HFS+, APM) and generic evidence
containers (EWF, AFF) are out of scope — they are independent crates a consumer
composes as needed; this reader has no knowledge of them.

1. **SUSP `ER` entry** — ✅ cheap, high value: positive on-disc identification of the extension protocol/version instead of inference.
2. **Apple `AA`/`BA` SUSP entries** — ⚠️ Apple's *ISO 9660 extension* (resource forks, Finder type/creator); medium value for Mac evidence; **confirm primary sources first** (least-cited area).
3. **Rock Ridge `PN` / `SF`** — ✅ low effort, completeness.
4. **Mode 2 / XA + 2336 / 2448 subchannel sectors** — 🟡 needed for VCD/CD-i/Photo CD/PSX and CD-Text; moderate effort (sector autodetect + subheader/EDC/ECC).
5. **Application structures (DVD-Video IFO, CD-Text)** — 🟡 niche; files remain recoverable without them.

---

## 5. Open citation items (close before implementing)

- **IEEE P1281 (SUSP)** primary document — P1282 only references it; needed to spec `ER`/`ST`/`PD`/`ES` record layouts. ✅(gap noted)
- **UEFI spec** for El Torito platform ID `0xEF`.
- **ECMA-130** (CD Mode 2 / XA / subchannel sector layout) — fetched 🟡 but not adversarially verified.
- **Apple TN1150** + `AA`/`BA` SUSP entry definitions. ⚠️
- **UDF 1.02 / 1.50 / 2.50** PDFs (only 2.00 / 2.01 / 2.60 verified this pass).
- Container specs via reference impls: **libmirage** (NRG/MDS/CCD), **libewf** (E01), **AFFLIB** (AFF).

## 6. Precision notes & one refuted claim

- **SVD vs EVD** share Volume Descriptor **type code 2**; they differ by the **version byte** (BP 7), not the type code. ✅
- **UDF 2.60 POW** is an *alternative* to VAT for next-gen write-once media (chiefly BD-R), **not** a wholesale replacement — CD-R/DVD-R/DVD+R retain VAT. ✅
- **RRIP 1.12 dropped the `RR` entry** that existed in 1.10. ✅
- ❌ **Refuted (1-2 vote):** the claim that "ECMA-119 4th ed. (2019) resulted from harmonizing ISO 9660 with Joliet / an ISO 9660:2013 amendment" did **not** survive verification — do not repeat it.

---

*Generated from an adversarially-verified deep-research pass. Verified rows cite
primary specs; 🟡/⚠️ rows are flagged for primary-source confirmation before any
spec-backed claim is made in code or court.*
