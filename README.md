# Config Audit

A Cisco IOS / IOS XE / NX-OS / ASA configuration auditor for network engineers. Paste or upload a pile of `show running-config` outputs and get a hardening score, ACL cleanup and the exact remediation commands, before an audit or a firmware or security push.

**Live:** https://config-audit.vercel.app

## The pain

Hardening reviews are usually grep plus a spreadsheet. Regex on lines breaks on block context (which `line vty` is that `transport input` under? is that text inside a banner?), and nobody can eyeball that ACL entry 50 is dead because entries 30 and 40 together already permit its traffic.

## Features

- **Real hierarchical parser** (indent-based parent/child blocks like ciscoconfparse) with banner and platform handling.
- **67 checks** grouped like the CIS Cisco IOS Benchmark with DISA STIG themes: AAA, SSH v2 and no telnet, exec-timeout, VTY access-class, type 7 and plain passwords, enable secret type 8/9, SNMP communities without ACLs, logging and NTP auth, unused services, banners, unused ports, routing protocol auth. Each has a severity, rationale, test and fix.
- **ACL reasoning**: each ACE is a union of 6-D boxes (protocol, source, destination, ports, established); box subtraction finds shadowed and redundant entries, even when several earlier entries cover one together. Also any/any permits, ACLs applied but undefined, unused ACLs and object-groups.
- **Remediation script** per device in the right parent context, shared ACLs defined once and first, a `reload in` safety net, plus a rollback script. Projected score after the fix.
- **Secret masking on import**: values are replaced, only the type and whether it is weak are kept.
  Masking is pattern-based and best effort, so review a config before sharing an export of it. Remediation scripts use fill-in tokens where a masked value is needed.
- **Truncated configs** are left out of grades until you confirm they are complete.
- Inventory (interfaces, VLANs, routing), fleet drift, waivers with reason and expiry, snapshots with fixed / new / regressed compare and a config diff, printable report, CSV export.
- Import: paste, files, zip (Oxidized, RANCID, archive folders), Ansible `ios_facts` JSON, with a validation report by line number.
- Local-first (IndexedDB). Optional email + password sign-in syncs audits through Supabase.

## Run locally

```sh
npm install
npm run dev      # http://localhost:5173
npm test         # engine tests
npm run build
npm run test:e2e # browser tests (see below)
```

### Tests

- `npm test` runs the engine unit tests (`node --test`, no browser).
- `npm run test:e2e` builds the app and runs the [Playwright](https://playwright.dev) suite in `e2e/` (Chromium) against that production build, served by `vite preview` on port 4417 (set `E2E_PORT` to use another). The first time, install the browser with `npx playwright install chromium` (add `--with-deps` on a fresh Linux machine). If `dist/` is already built, `npx playwright test` skips the rebuild; `npx playwright test -g "waiver"` runs matching tests only.
- The suite covers the sample fleet (scores, ACL shadowing), remediation and rollback scripts with their downloads, pasted and zipped imports with secret masking checked in the page, downloads and IndexedDB, waivers, persistence across a reload, and bad input (wrong format, empty, truncated). Every test starts with an empty browser profile, signed out; requests to any host other than the preview server are blocked, and uncaught page errors fail the test.
- `e2e/known-bugs.spec.ts` holds tests for open issues, marked as expected failures until the issue is fixed.
- GitHub Actions (`.github/workflows/ci.yml`, job `test`) runs install, build, unit tests and the E2E suite on every pull request and on pushes to `main`. Vercel deploys only `main`; pull request branches get no preview (`git.deploymentEnabled` in `vercel.json`).

Copy `.env.example` to `.env` for sync (public Supabase URL and publishable key). Everything works without it.

Two samples ship with the app: a synthetic three-device fleet (RFC 1918 / RFC 5737 addresses only) and the public [Batfish example network](https://github.com/batfish/batfish/tree/master/networks/example/live/configs) (six real lab routers, Apache-2.0, bundled unmodified). The importer is also regression-tested against the ciscoconfparse fixtures (IOS, NX-OS, ASA); see /docs#tested.

Built by Aryan Kansagara.
