I have all the research and adversarial verification data I need to build this matrix. This is a synthesis task — no tool calls required. Let me produce the markdown faithful to the sources.

# Keywright Compliance Tag Matrix

Scope: OpenPGP provisioning on YubiKey 5 FIPS Series (firmware 5.7.4, CMVP cert #5291). As-of date for all stances: **2026-06-20**. Stances reflect the verified research; the adversarial pass returned **confirmed-with-caveats** for every framework checked (FIPS 140-3, FIPS 186-5, CNSA 2.0).

Legend: ★ recommended · ✓ approved · ⚠ allowed-with-conditions · ✗ forbidden · – not addressed

---

## 1. Matrix

| Option | FIPS 140-3 (module/hardware) | FIPS 186-5 / SP 800-186 (algorithm) | SP 800-57 Pt.1 r5 (strength/lifetime) | CNSA 2.0 (NSS suite) | BSI TR-02102-1 (2026-01) |
|---|---|---|---|---|---|
| **RSA-2048** (certify/sign/auth) | ✓ approved — CAVP-tested in cert #5291 | ✓ approved — min RSA size, 112-bit | ⚠ conditions — 112-bit, **disallowed for applying protection from 2031** | ✗ forbidden — below CNSA 1.0 RSA≥3072 floor | ✗ deprecated — below 3000-bit min; transitional conformance expired end-2023 |
| **RSA-3072** (certify/sign/auth) | ✓ approved — CAVP-tested | ✓ approved — 128-bit | ✓ approved — 128-bit, survives 2031 transition | ⚠ deprecated — meets CNSA 1.0 floor, **transitional only, retire by 2030/2033** | ★ recommended — meets 3000-bit min |
| **RSA-4096** (certify/sign/auth) | ✓ approved — CAVP-tested, largest RSA in applet | ✓ approved — ≥128-bit | ✓ approved — ≥128-bit, acceptable indefinitely | ⚠ deprecated — exceeds floor, **transitional only** | ★ recommended — exceeds 3000-bit min |
| **RSA encryption subkey** (RSA decipher, OpenPGP) | ✗ forbidden — **blocked in OpenPGP FIPS Approved Mode** (use ECDH P-curve) | n/a (encryption-use) | (key-transport <2 yr if used) | ✗ forbidden — RSA transitional/deprecated | ⚠ conditions — RSA key exchange recommended **only until end-2031** |
| **ECDSA P-256** (nistp256) | ✓ approved — CAVP-tested, OpenPGP SigGen | ✓ approved — SP 800-186 recommended, 128-bit | ✓ approved — 128-bit, indefinite | ✗ forbidden — CNSA is P-384 only | ⚠ conditions — meets q≥2²⁵⁰; **not named in Table B.3 (only Brainpool listed)** |
| **ECDSA P-384** (nistp384) | ✓ approved — CAVP-tested | ✓ approved — recommended, 192-bit | ✓ approved — 192-bit, indefinite | ⚠ deprecated — **only CNSA-acceptable classical curve, retire by 2030/2033** | ⚠ conditions — meets q≥2²⁵⁰; not named in Table B.3 |
| **ECDSA P-521** (nistp521) | ✓ approved — CAVP-tested | ✓ approved — recommended, 256-bit | ✓ approved — 256-bit, indefinite | ✗ forbidden — not in CNSA suite (P-384 only) | ⚠ conditions — meets q≥2²⁵⁰; not named in Table B.3 |
| **EdDSA Ed25519** (sign/auth) | ✓ approved — CAVP-tested (Curve ED-25519); only Edwards curve in module | ✓ approved — FIPS 186-5 added EdDSA (2023), 128-bit | ✓ approved — EdDSA "approved in FIPS 186", 128-bit, indefinite | ✗ forbidden — not in any CNSA tier | – not addressed — **absent from TR-02102-1; not forbidden, but cannot claim "recommended"** |
| **EdDSA Ed448** (sign/auth) | ✗ unavailable — **absent from cert #5291** (only Ed25519 in module) | ✓ approved — FIPS 186-5 / SP 800-186 approve Edwards448 | ✓ approved-in-standard (224-bit) | ✗ forbidden — not in CNSA | – not addressed |
| **ECDH X25519 / cv25519** (encryption subkey) | ✗ forbidden — **blocked in OpenPGP FIPS Approved Mode** | ✗ forbidden — IG C.K Res.5: X25519/X448 ECDH **not approved for key agreement**; not in SP 800-56A r3 | – not addressed — not an approved key-establishment scheme (not banned, just unlisted) | ✗ forbidden — not a CNSA algorithm; also blocked in module | – not addressed — absent from TR-02102-1 |
| **ECDH on NIST P-256/384/521** (encryption subkey) | ✓ approved — KAS-ECC-SSC (SP 800-56A r3); FIPS-conformant encryption path | ✓ approved — EC key establishment per SP 800-186 Table 2 | ✓ approved — static key-agreement, 128/192/256-bit | ⚠ P-384 only deprecated/transitional; P-256/P-521 ✗ | ⚠ conditions — ECDH recommended (until end-2031 classical); P-curves not named in Table B.3 |
| **brainpoolP256r1** (ECDSA/ECDH) | ⚠ conditions — Non-Approved-but-Allowed per **IG C.A** (not NIST-approved) | ⚠ conditions — SP 800-186 App. H "allowed for interoperability" only | ⚠ conditions — allowed-for-interop, ~128-bit, not Recommended | ✗ forbidden — not in CNSA suite | ★ recommended — **explicitly named in Table B.3** |
| **brainpoolP384r1** (ECDSA/ECDH) | ⚠ conditions — Non-Approved-Allowed per IG C.A | ⚠ conditions — App. H interop-only | ⚠ conditions — ~192-bit, interop-only | ✗ forbidden — not in suite | ★ recommended — named in Table B.3 |
| **brainpoolP512r1** (ECDSA/ECDH) | ⚠ conditions — Non-Approved-Allowed per IG C.A | ⚠ conditions — App. H interop-only | ⚠ conditions — ~256-bit, interop-only | ✗ forbidden — not in suite | ★ recommended — named in Table B.3 |
| **SHA-256** | ✓ approved — CAVP-tested (FIPS 180-4) | ✓ approved | ✓ approved — 128-bit collision strength | ⚠ conditions — **below CNSA hash floor for general use** (SHA-384/512); OK only inside LMS/XMSS | ★ recommended — Table 4.1 |
| **SHA-384** | ✓ approved — CAVP-tested | ✓ approved | ✓ approved — 192-bit | ✓ approved — core CNSA hash | ★ recommended — Table 4.1 |
| **SHA-512** | ✓ approved — CAVP-tested | ✓ approved | ✓ approved — 256-bit | ✓ approved — CNSA 2.0 (SHA-384/512) | ★ recommended — Table 4.1 |
| **Subkey expiration / cryptoperiod** | – not addressed — module validation is silent | – not addressed — 186-5/800-186 silent | ★ recommended — Table 1 concrete numbers (see §3) | – not addressed (only migration deadlines) | – not addressed (only algorithm horizons; see §3) |

---

## 2. Display-tag recommendations (per option)

Show the **regime-qualified** tag, never a bare "FIPS" or "approved." Options flagged ⚠ MISLEAD are where a naive tag would actively deceive.

| Option | Recommended Keywright label |
|---|---|
| **RSA-2048** | "FIPS 140-3 / 186-5 approved · SP 800-57: disallowed for new protection from 2031 · CNSA: forbidden · BSI: deprecated (below 3000-bit)" |
| **RSA-3072** | "FIPS approved · SP 800-57 128-bit (survives 2031) · CNSA transitional-only · BSI recommended" |
| **RSA-4096** | "FIPS approved · SP 800-57 ≥128-bit · CNSA transitional-only · BSI recommended" |
| **RSA encryption subkey** | ⚠ MISLEAD — "Blocked in YubiKey OpenPGP FIPS Approved Mode — use an ECDH NIST P-curve encryption subkey instead." A bare "RSA = FIPS approved" tag is wrong for the *decipher* path. |
| **ECDSA P-256** | "FIPS 186-5 approved (NIST-recommended curve) · CNSA: forbidden (P-384 only) · BSI: meets criteria but not Table-B.3-named" |
| **ECDSA P-384** | "FIPS 186-5 approved · **CNSA 1.0 classical curve (transitional, retire ≤2030/2033)** · BSI: meets criteria" |
| **ECDSA P-521** | "FIPS 186-5 approved · CNSA: forbidden (not in suite) · BSI: meets criteria" |
| **Ed25519** | ⚠ MISLEAD — "FIPS 186-5 approved (2023) AND in validated YubiKey module #5291 · **CNSA: forbidden · BSI TR-02102-1: not addressed (neither recommended nor forbidden)**." Do NOT show a bare "FIPS" — it is FIPS-approved but not CNSA and not a BSI-named mechanism. |
| **Ed448** | ⚠ MISLEAD — "FIPS 186-5 approved-in-standard but **NOT in the validated YubiKey module (#5291) — unusable in approved mode**." A bare "FIPS 186-5 approved" implies it works on the device; it does not. |
| **X25519 / cv25519** | ⚠ MISLEAD — "**NOT FIPS-approved for key agreement (IG C.K Res.5) · blocked in YubiKey OpenPGP FIPS Approved Mode · forbidden under CNSA · not addressed by BSI**." This is the single most dangerous default (GnuPG's modern default) — never tag as "approved." |
| **ECDH NIST P-256/384/521** | "FIPS-approved encryption-subkey path (SP 800-56A r3) · use instead of RSA-decrypt/X25519 in FIPS mode" |
| **brainpoolP256r1/384r1/512r1** | ⚠ MISLEAD — "**BSI recommended (Table B.3)** but **NOT NIST-approved** — Non-Approved-but-Allowed in FIPS module (IG C.A) · **forbidden under CNSA**." A naive "FIPS" or "approved" tag misrepresents NIST status; conversely a "non-compliant" tag misrepresents BSI status. Tag must name the regime. |
| **SHA-256** | "FIPS/186-5/800-57/BSI approved · **CNSA: below hash floor for general use (SHA-384/512 required)**" |
| **SHA-384** | "Approved across all five regimes (FIPS, 186-5, 800-57, CNSA, BSI)" |
| **SHA-512** | "Approved across all five regimes" |

---

## 3. Key lifetime / cryptoperiod guidance (concrete numbers)

These drive Keywright's expiration **defaults**. Distinguish operational cryptoperiod (rotation hygiene) from algorithm-strength sunset (when the math is retired).

| Framework | Lifetime guidance | Notes |
|---|---|---|
| **SP 800-57 Pt.1 r5, Table 1** (the authoritative cryptoperiod source) | Private **signature** key (certify/sign subkey): **1–3 years**, destroy at expiry. **Authentication** key: **1–2 years**. Static **key-agreement** (ECDH encryption subkey): **1–2 years**. Public verification key: "several years." | A **1–2 year renewable** subkey default is squarely compliant. **Encryption/decryption private key may need to outlive its cryptoperiod** to decrypt old mail — do NOT auto-destroy it the way you destroy a signing key. |
| **FIPS 140-3 / cert #5291** | Not addressed. Module enforces no expiration; choosing finite vs. non-expiring does not change FIPS-approved status. | Treat expiration as an SP 800-57 policy choice, not a FIPS gate. |
| **FIPS 186-5 / SP 800-186** | Not addressed (silent). | Defers to SP 800-57. |
| **CNSA 2.0** | No per-key cryptoperiod. **Migration deadlines** only: classical keys must be out of use by the use-case "exclusive CNSA 2.0" date — **2030** (sw/fw signing, traditional networking), **2033** (web/cloud, OS); all NSS quantum-resistant by **2035** (NSM-10). | For NSS, set classical-key expiration **no later than the 2030–2033 window** for its use. Cryptoperiod hygiene still defers to SP 800-57. |
| **BSI TR-02102-1 (2026-01)** | No fixed validity in years. **Algorithm horizons**: classical asymmetric key agreement/encryption (RSA key-transport, ECDH) recommended **only until end-2031** (end-2030 for very-high-protection); classical signatures (RSA, ECDSA) until **end-2035**; hybrid PQC after. ~6–7 yr prediction horizon. | **Encryption subkey expiry ≤ end-2031; signing/certify ≤ end-2035** for strict alignment. Encryption and signing subkeys may have *different* effective compliance lifetimes. |

**Suggested default**: 1–2 year renewable subkeys (SP 800-57-aligned), with a hard ceiling so that an encryption subkey does not validate past **end-2031** (BSI) and any NSS-targeted classical key expires before **2030/2033** (CNSA). Note the **2030/2031 SP 800-57 dates are an algorithm-strength sunset (112→128-bit), not a cryptoperiod** — RSA-2048 becomes disallowed for *applying* protection in 2031 but stays legacy-valid for verify/decrypt.

---

## 4. Hardware note

- **Validated module**: "YubiKey 5 Cryptographic Module," single-chip SLE78CLUFX5000P, **firmware 5.7.4**, **CMVP FIPS 140-3 Certificate #5291**, **Overall Level 2 / Physical Security Level 3**, validated **2026-05-22**, sunset **2031-05-21**. Covers the **YubiKey 5 FIPS Series** form factors. (Verified directly against the CMVP certificate page and 140sp5291.pdf.)
- **Superseded**: prior **FIPS 140-2 cert #3907** (firmware 5.4.x) — fewer OpenPGP algorithms (no RSA-3072/4096, no Ed25519), moving to Historical. Tie any "current FIPS" posture to **5.7.4 / #5291**.
- **Not validated at all**: standard (non-FIPS) YubiKey 5 and Security Key series carry **no CMVP validation**. They *do* support cv25519/brainpool, but using those is outside any FIPS Approved Mode.
- **OpenPGP applet (v3.4) in FIPS Approved Mode** — supported: RSA-2048/3072/4096 (sign/auth/certify), ECDSA P-256/384/521, Ed25519, ECDH on NIST P-256/384/521 (encryption subkey), SHA-256/384/512, brainpoolP256r1/384r1/512r1 (Non-Approved-but-Allowed, IG C.A).
- **Blocked in OpenPGP FIPS Approved Mode**: **RSA decryption** (RSA encryption-subkey decipher path), **X25519/cv25519**, **secp256k1**, RSA-1024, 3DES. (Block list and PIN rules come from **Yubico operational docs**, not the CMVP policy; the approved list is from the CMVP policy.)
- **Operational constraints**: User PIN, Admin PIN, and Reset Code (if set) must be changed from defaults to **≥8 characters** (stricter than the policy's 6-byte/48-bit crypto floor — not a contradiction); device refuses credential creation until in Approved Mode; all NFC must use an SCP03/SCP11 secure channel.
- **RSADP clarification**: the SP 800-56B/56B-r2 RSA Decryption Primitive on cert #5291 belongs to the **PIV** "General AUTH Decrypt" service, **not** OpenPGP decipher (which is ECDH-only). Minor wording tension: the SSP table groups PIV+OpenPGP private-key objects together, but no OpenPGP RSA-decrypt *service* exists in approved mode.
- **P-224**: CAVP-tested in the module but **not offered by the OpenPGP key-generation service** (P-256/384/521 only) — not a practical OpenPGP option.

---

## 5. Policy-engine implications

**"FIPS-only" profile** (must stay in YubiKey OpenPGP FIPS Approved Mode):
- **Permit**: RSA-2048/3072/4096 (sign/auth/certify), ECDSA P-256/384/521, Ed25519, ECDH NIST P-256/384/521 (encryption subkey), SHA-256/384/512.
- **Permit-with-flag** (works in approved mode but NOT NIST-approved): brainpoolP256r1/384r1/512r1 — only if the deployment accepts IG C.A "allowed" non-NIST curves. Many US federal procurements expect strict NIST curves; default to excluding brainpool under "strict FIPS."
- **Forbid**: X25519/cv25519, RSA encryption subkeys (RSA decipher), secp256k1, Ed448. Require encryption subkey = ECDH NIST P-curve. Enforce ≥8-char PINs.

**"CNSA 2.0" profile** (NSS) — note **no YubiKey can be truly CNSA 2.0-conformant** (requires ML-KEM-1024 / ML-DSA-87, which no shipping OpenPGP applet implements). Best achievable is **CNSA-transitional classical**:
- **Permit (transitional only)**: RSA-3072/4096, ECDSA/ECDH **P-384**, SHA-384/512. All carry a "retire by 2030/2033" flag.
- **Forbid**: RSA-2048, **P-256, P-521**, Ed25519, X25519, all brainpool, SHA-256 for general use. Ensure `nistp384` maps to "CNSA-acceptable transitional" and the engine refuses nistp256/nistp521/brainpool/Ed25519/cv25519 when CNSA is the goal.

**"BSI TR-02102-1" profile**:
- **Permit/recommend**: RSA-3072/4096, **brainpoolP256r1/384r1/512r1** (the explicitly named curves), SHA-256/384/512.
- **Permit-with-condition**: NIST P-256/384/521 (meet q≥2²⁵⁰ but not named in Table B.3 — residual interpretive uncertainty on whether NIST curves count as "from a trustworthy authority").
- **Not-addressed (cannot claim conformant)**: Ed25519, X25519/cv25519 — absent from Part 1 (neither recommended nor forbidden).
- **Deprecated/forbid**: RSA-2048.
- Apply algorithm horizons: encryption subkey expiry ≤ end-2031; signing ≤ end-2035.

**Conflicts a tool must surface** (the same option gets opposite verdicts across regimes):

| Option | The conflict |
|---|---|
| **Ed25519** | FIPS-approved AND in the validated module, but **CNSA-forbidden** and **BSI-not-addressed**. A device default common in GnuPG; compliant under FIPS, non-compliant under CNSA, unclaimable under BSI. |
| **Brainpool curves** | **BSI ★recommended** vs **NIST/FIPS ⚠Non-Approved-Allowed** vs **CNSA ✗forbidden**. The starkest cross-regime split — a single "compliant/non-compliant" tag is impossible; must name the regime. |
| **X25519 / cv25519** | **GnuPG's modern default**, yet ✗forbidden under FIPS and CNSA and –not-addressed by BSI. The most likely user mistake. Engine should block it in any FIPS or CNSA profile. |
| **ECDSA P-256 / P-521** | FIPS/BSI-OK but **CNSA-forbidden** (CNSA is P-384-only). A "drudh-style" hardened setup picking P-521 for max strength is *non-compliant* with CNSA precisely because it is not P-384. |
| **SHA-256** | Fine under FIPS/186-5/800-57/BSI but **below the CNSA general-use hash floor**. |
| **RSA-2048** | FIPS/186-5-approved but **CNSA-forbidden, BSI-deprecated, and SP 800-57-disallowed for new protection from 2031**. "FIPS-approved" alone overstates its standing. |

---

## 6. Caveats & freshness (re-check before publishing compliance claims)

**Time-sensitive / must re-verify:**
- **Module-validation lag is the core trap**: "approved in the standard" ≠ "available in the validated module." Ed448 is FIPS 186-5-approved but absent from cert #5291; brainpool is BSI-recommended but only IG C.A-Allowed in the module. Always check both layers.
- **X25519 trajectory**: blocked because SP 800-56A r3 does not list X25519/X448 key agreement (IG C.K Res.5). **Correction from adversarial pass**: the claim that this "could change in a future SP 800-56A revision" is too optimistic — NIST's **2025-07-29** announcement explicitly states it **does not propose to approve** X25519/X448, treating them as secondary to the PQC transition. Current trajectory is **active non-approval**, not pending addition.
- **CNSA PQC timeline** (re-check as deadlines approach): support/exclusive dates — sw/fw signing & networking **exclusive 2030**; web/cloud & OS **exclusive 2033**; new NSS acquisitions CNSA-2.0 from **Jan 1 2027**; all NSS quantum-resistant **2035** (NSM-10). Additional **CNSSP-15 enforcement overlay** (distinct instrument): fielded non-compliant equipment phased out by **Dec 31 2030**, full enforcement **Dec 31 2031**.
- **CNSA citation currency**: cite **PP-24-4014, December 2024, Ver. 2.1** as the current algorithms reference (replaced Kyber/Dilithium pre-standard names with ML-KEM/ML-DSA), not only the Sep 2022 PP-22-1338 Ver. 1.0. Substantively unchanged (same algorithms, params, timeline).
- **SP 800-57 Rev. 6 is DRAFT only** (IPD 2025-12-05); **SP 800-131A Rev. 3 still draft**. Binding stance remains **Rev. 5 + SP 800-131A Rev. 2**. Re-check if either finalizes.
- **#3907 sunset**: prior FIPS 140-2 cert moving to Historical (~Sept 2026); ensure tooling targets #5291.

**Remaining uncertainty (not fully verified):**
- **BSI NIST-curve status**: TR-02102-1 names only Brainpool in Table B.3. Whether NIST P-curves qualify under Remark B.1's "standardised values from a trustworthy authority" is **not stated explicitly** — this is genuine interpretive ambiguity, hence the ⚠ rather than ★/✗ for P-curves under BSI.
- **OpenPGP-applet 5.7-specific enumeration**: the FIPS-mode block list and 8-char PIN come from Yubico operational docs (authoritative for vendor approved-mode behavior); the curve set was confirmed against the firmware 5.2.3 OpenPGP-3.4 page, not a 5.7-specific applet enumeration. The approved list is grounded in the CMVP policy. Keep that source division explicit.
- **CNSA primary PDFs**: media.defense.gov returned HTTP 403 to automated fetchers in both research and verification; the algorithm set, parameters, and timeline were corroborated via the NIST CMVP records plus multiple independent NSA-quoting analyses, **not** a verbatim read of the NSA PDFs. A human should confirm against the official PDFs before publishing.
- **RSA-4096 strength**: no dedicated SP 800-57 Table 2 row; treated as ≥128-bit (interpolated between 3072=128 and 7680=192 per Rev.5's "unlisted sizes"/IG 7.5 note) — buys margin but not a strength-tier upgrade over 3072 in NIST accounting.
- **Nothing was exercised on physical hardware** — all stances are verified end-to-end against primary CMVP/NIST/Yubico/BSI sources, not tested on a YubiKey.
