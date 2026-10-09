# Dependency static audit — 2026-10-09

This is a source-code audit. No downloaded Windows executables or upstream build scripts were executed. No ISO was built and no VM acceptance result is claimed.

## Checked repositories

| Repository | Checked commit | Scope |
| --- | --- | --- |
| `adavak/Win_ISO_Patching_Scripts` | `d08899ae5f49af9bef5b8f6ab0800808a0ce4b06` | Start.cmd, W10UI.cmd/ini/readme, update manifest generator, all manifests, workflow |
| `adavak/win_iso_zip` | `baa6ed51edaaf7199a1026d4bbdf86b776b87df6` | Only tracked file is README.md containing `Initial`; no reusable ZIP implementation exists at this snapshot |
| `abbodi1406/BatUtil` | `2c05458f5962fa7b12b5e3cb84a5349660727ea7` | Upstream W10UI v10.65 implementation and README |

No AGENTS.md was found in the cloned repositories. Sources are under sibling work/ directories. Repository links below pin the inspected commits.

## Real meaning of LtscAddEP

[Upstream W10UI README, lines 162–165](https://github.com/abbodi1406/BatUtil/blob/2c05458f5962fa7b12b5e3cb84a5349660727ea7/W10UI/README.md#L162-L165) says `LtscAddEP=1` installs applicable enablement packages for LTSC editions on builds 26100 and later. `=2` forces inapplicable EPs, with 22H2 on LTSC 2021 as its example. Default upstream is zero.

[Upstream code, lines 2071–2082](https://github.com/abbodi1406/BatUtil/blob/2c05458f5962fa7b12b5e3cb84a5349660727ea7/W10UI/W10UI.cmd#L2071-L2082) matches Edition dependencies in update.mum against the target image's installed edition package .mum files. A missing match is skipped except for forced `=2`, which directly queues child enablement .mum files. A matching LTSC package is only queued with `=1`. This is a tool-level package filter; it does not establish Microsoft support, guarantee all prerequisites, or justify any arbitrary target build.

The tool recognizes `Microsoft-Windows-Ge-Client-Server-26340-Version-Enablement-Package` at [line 2825](https://github.com/abbodi1406/BatUtil/blob/2c05458f5962fa7b12b5e3cb84a5349660727ea7/W10UI/W10UI.cmd#L2825). This is evidence only that it knows the package naming pattern. It does not prove KB5122776, KB5127753, or target 26340.9616 mapping or package applicability. Those claims require independent Microsoft release metadata, package identities and DISM evidence.

## Concrete audit findings

1. **TLS verification disabled.** [Start.cmd:309–311](https://github.com/adavak/Win_ISO_Patching_Scripts/blob/d08899ae5f49af9bef5b8f6ab0800808a0ce4b06/Start.cmd#L309-L311) uses aria2 with `--check-certificate=false`. Experimental downloads should enforce TLS verification, use an explicit official-host allowlist, validate redirect destinations, reject path traversal names, and verify manifest-pinned SHA-256 before servicing. XML parsing of all 27 manifests found 249 package entries, all with SHA-1 only. Their URLs use `catalog.s.download.windowsupdate.com` (214) or `catalog.sf.dl.delivery.mp.microsoft.com` (35). Hostname labels and SHA-1 are not substitutes for Microsoft provenance and package-catalog signature verification.

2. **Aggressive defaults.** [W10UI.ini:8–18](https://github.com/adavak/Win_ISO_Patching_Scripts/blob/d08899ae5f49af9bef5b8f6ab0800808a0ce4b06/W10UI.ini#L8-L18) enables Cleanup=1, ResetBase=2 and LtscAddEP=1. ResetBase removes superseded components and upstream explicitly warns about breaking Reset this PC in W10UI.cmd:29. Disable cleanup/resetbase for initial experiments; never enable force EP. Keep source image and service logs.

3. **Silent skip / weak failure handling.** W10UI queues and adds packages at adavak W10UI.cmd:1709–1744. The `:dNUL` handler at lines 1978–1980 only re-queries packages for error 1726; it does not reject arbitrary failing Add-Package results. EP filtering can skip a package and proceed. A successful tool process or an ISO filename is therefore insufficient. Experimental driver must stop on unacceptable exit codes, inspect package installed/pending states, then verify real edition/version after first boot.

4. **More mutations than package servicing.** adavak custom W10UI.cmd:1794–1797 (`ltscfix=1` default) provisions a bundled VP9 Appx and license file. Lines 1798–1852 implement optional default-user ContentDeliveryManager/Explorer/Search/GameBar and reserved-storage/OOBE registry changes. Most optional tweaks are currently zero. Disable all optional tweaks and VP9 provisioning for the first experimental baseline. There is no reason to include unrelated settings in a compatibility experiment.

5. **ACL operations found are on servicing internals.** W10UI.cmd:1914–1919 saves ACL, takes ownership of Servicing/Packages .mum, copies a replacement, resets TrustedInstaller owner and restores ACL. Lines 2424–2429 and 2448–2453 do related operations on WinSxS/Manifests. Lines 3144–3175 take ownership to delete component-store temporary data. No blanket user-profile ACL reset, no ShellNew removal and no direct firewall/DNS/proxy/BFE/TUN disabling were found. Static inspection does not explain the user's earlier profile permission symptom; VM reproduction is required. Also, `--no-acls` / `/NoAcl:all` occurrences predominantly unpack update-container payloads, not `install.wim` deployment to a user profile; do not assert these automatically corrupt user ACLs.

6. **Cleanup=0 is not zero mutation.** W10UI.cmd:3104 calls `:cleanmanual` even with Cleanup=0. The adavak variant additionally removes Windows logs, SetupDU SPDX data, `sources/_manifest`, and `sources/testplugin.dll` (3182–3190 and 3996). Prefer a new native DISM driver for the smallest auditable MVP instead of running the existing Start.cmd/W10UI path. If W10UI is used later, document all inherited actions and preserve logs outside the serviced tree.

7. **Existing branch routing is retail-oriented.** Start.cmd:224 maps 26200–26300 to 26100 and then selects Scripts/script_26100_x64.meta4. It does not map 26340, and the current manifest contains KB5121794, KB5124010 and other retail-associated packages. Do not repurpose that filename or replace retail versions in place.

8. **Upstream manifest automation writes and dispatches.** [.github/workflows/update-meta4.yml](https://github.com/adavak/Win_ISO_Patching_Scripts/blob/d08899ae5f49af9bef5b8f6ab0800808a0ce4b06/.github/workflows/update-meta4.yml) has contents/actions write, deletes older workflow logs (line 32), commits/pushes manifests, tags/releases, and dispatches `adavak/win_iso_build --ref main` (line 116). Experimental workflow should be manually dispatched, immutable-input driven, fork/branch-only, minimal permissions, SHA-pinned Actions, and not delete evidence or call the upstream workflow.

9. **Tool provenance not fully established by repository commit.** Bundled binaries are pinned as bytes by commit but there is no checked tool-lock provenance metadata / expected SHA-256 list. Native Microsoft ADK DISM/oscdimg from a legitimate acquisition plus verified upstream 7-Zip can minimize dependency exposure. Signing evidence is needed on Windows; this macOS static audit cannot confirm Authenticode/catalog trust chains.

## Minimal safe route

Add a separate experimental directory and manually dispatched workflow; preserve the existing production entry points byte-for-byte. Start with a candidate manifest explicitly marked unverified, so preflight fails closed. Verified manifest needs Microsoft release URL, exact UUP update ID, build/revision, language/architecture, licensed base ISO identity and SHA-256, package SHA-256 and Microsoft signatures, all checkpoints/SSU prerequisites, ordered install roles, tool versions/hashes and independent evidence status.

The first Windows-native implementation should export only the chosen EnterpriseS index from the legitimate zh-CN x64 LTSC 2024 source, copy media to a fresh NTFS working directory, retain source ACLs, mount the copy, record default-profile ACL/SDDL and package list, inspect each verified CAB's DISM applicability and identity, apply prereqs/LCU/EP with checked exit codes without `/IgnoreCheck`, and compare the original ACL/default-user hive with the serviced copy. Reject mismatch and unexpected profile-policy changes. No activation modifications, edition conversion, component removal, ResetBase, default-account tweaks or network configuration changes. Record direct DISM log paths, manifest/tool hashes and SHA-256 output alongside the ISO.

Never name the output as an official supported LTSC edition. An enabled LTSC image remains an unofficial hybrid, even when every package is Microsoft signed and accepted by CBS.

The next acceptance stage requires actual clean installation into an isolated x64 VM. Validate edition and CurrentBuild/UBR and package states after reboot, normal-user creation in the user's profile/Desktop/Documents, Explorer New > text/folder menus, no user ACL ownership changes, Windows Update scan/download/install/reboot, SFC/DISM health, Defender and Secure Boot. Compare with a clean LTSC baseline and a stock 26340 Insider installation. For Reality/sing-box record an exact legitimate binary version/hash and safe local test configuration, test DNS/TCP/UDP/IPv4/IPv6/TUN and wake/reboot behavior, then compare the results between baselines. Do not use static build success as a networking result or include private credentials in audit artifacts.

## Local SHA-256 observations, bundled x64 tools

These hashes identify inspected repository bytes only; they do not independently certify their origin.

| File | SHA-256 |
| --- | --- |
| bin/bin64/7z.exe | 83967f1b02b43c4efeda302795722c809e0e81b8307de73558d10484d5676a7d |
| bin/bin64/PSFExtractor.exe | b8a08dd9592e64843056cf5fe518e782fd7ed517d1ee32b70a99b7d7e5767f6c |
| bin/bin64/aria2c.exe | be2099c214f63a3cb4954b09a0becd6e2e34660b886d4c898d260febfe9d70c2 |
| bin/bin64/oscdimg.exe | 18f3ee46ff2e1d8f4e95ebb84d0ea37d6aad142e6fac8f09210ec521c171ed7d |
| bin/bin64/wimlib-imagex.exe | 34c0c4165591ad1f592837ed99d08273c58d6ed3fe0ed6360cf34e7b0739b353 |
| bin/bin64/7z.dll | 69fd4df057985c40e510e2fac182881c7f85e90aa13ec703f763a8fdb2ce61f8 |
| bin/bin64/libwim-15.dll | ba853ee1e3fc5f5798581f02e8e066ba07a0a2375f0bf444fe981431fd508495 |
