import { RULES, SEV_WEIGHT } from './engine/rules.ts'
import { Sev } from './components.tsx'
import { Code, Link } from './ui.tsx'

const CLI = `terminal length 0
show running-config
! NX-OS: same commands. ASA: "terminal pager 0" then "show running-config"
! Save from your terminal client's log, or straight to a server:
copy running-config scp://backup@192.0.2.40/configs/BR-RTR-01.cfg`

const ARCHIVE = `archive
 path flash:archive/$h-
 write-memory
 time-period 1440
! later, list and fetch:
show archive
copy flash:archive/BR-RTR-01-3 scp://backup@192.0.2.40/configs/`

const OXIDIZED = `# Oxidized git output: zip the repo working tree (one file per device)
cd /var/lib/oxidized/configs.git && git archive --format=zip HEAD -o ~/configs.zip
# RANCID: zip the configs folder of each group
cd /var/lib/rancid/core/configs && zip -r ~/rancid-core.zip .`

const ANSIBLE = `# playbook.yml
- hosts: cisco
  gather_facts: no
  tasks:
    - cisco.ios.ios_facts:
        gather_subset: [config]
    - ansible.builtin.copy:
        content: "{{ ansible_facts | to_nice_json }}"
        dest: "facts/{{ inventory_hostname }}.json"
      delegate_to: localhost
# Upload the facts/*.json files (or a zip of the folder).`

export default function Docs() {
  const cats = [...new Set(RULES.map(r => r.category))]
  return (
    <section className="page narrow docs">
      <div className="eyebrow">Docs · updated November 2026</div>
      <h1>Collecting configs and reading the results</h1>
      <p className="lead-dark">Config Audit needs the text of each device's running configuration. Nothing connects to your devices; you bring the files.</p>

      <h2 id="collect">1. Get the configs out</h2>
      <h3>From the CLI</h3>
      <p>Disable paging first, or the capture fills with <code>--More--</code> prompts (the validation report flags them by line number).</p>
      <Code label="IOS / IOS XE / NX-OS / ASA" code={CLI} />
      <h3>From the IOS archive</h3>
      <p>If you already use <code>archive</code>, each saved version is a full config with the hostname in the file name.</p>
      <Code label="IOS archive" code={ARCHIVE} />
      <h3>From Oxidized or RANCID</h3>
      <p>Both keep one plain-text file per device. Zip the folder and drop the zip; README and dot files are skipped, and RANCID's <code>!</code> header lines are ignored as comments.</p>
      <Code label="Shell" code={OXIDIZED} />
      <h3>From Ansible</h3>
      <p>The <code>ios_facts</code> module with the <code>config</code> subset returns <code>ansible_net_config</code>. Upload the JSON; every device in it is found.</p>
      <Code label="Ansible" code={ANSIBLE} />

      <h2 id="masking">2. What happens to secrets</h2>
      <p>Before anything is stored, every secret value is replaced: enable and user passwords, line passwords, SNMP communities, TACACS+/RADIUS keys, key chains, OSPF and BGP keys, NTP keys and IKE pre-shared keys. The encoding digit stays (so "type 7" is still visible) and the value becomes <code>&lt;masked&gt;</code> or <code>&lt;masked:weak&gt;</code>. Weak means: plain text, type 7 (reversible), type 5 or 4, a legacy ASA hash, or a community that is a default, a dictionary word or shorter than 10 characters. The original text is never written to IndexedDB, exports or the cloud.</p>

      <h2 id="score">3. How the score works</h2>
      <p>Each rule that applies to the platform has a weight by severity: critical {SEV_WEIGHT.critical}, high {SEV_WEIGHT.high}, medium {SEV_WEIGHT.medium}, low {SEV_WEIGHT.low}. A rule fails if it has at least one open finding. Score = weight of passing rules / weight of all evaluated rules × 100. Grades: A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 55. A waived finding does not count until its expiry date passes. The fleet score is the mean of device scores.</p>

      <h2 id="acl">4. ACL analysis</h2>
      <p>Every IPv4 ACE (named and numbered IOS ACLs, NX-OS ACLs with prefixes, ASA ACLs with masks and object-groups) becomes a set of boxes over protocol, source range, destination range, source port, destination port (or ICMP type and code) and the TCP established flag. For each entry, all earlier entries that overlap are subtracted from it. If nothing remains, it is <b>shadowed</b> (some earlier entry with the other action catches its traffic) or <b>redundant</b> (same action). Entries using keywords the engine does not model (time-ranges, DSCP, TCP flags) are never reported as covered, so the analysis errs on the side of silence.</p>

      <h2 id="rules">5. The rule pack ({RULES.length} checks)</h2>
      <p className="muted small">Grouped like the CIS Cisco IOS Benchmark (management plane, control plane, data plane) with DISA STIG network-device themes. The "Benchmark area" column names the area, not an official control number: numbering changes between benchmark versions (assumption as of CIS IOS 16/17 benchmarks and the 2024–2025 Cisco IOS XE STIGs).</p>
      {cats.map(c => (
        <div key={c}>
          <h3>{c}</h3>
          <div className="table-wrap">
            <table className="tbl rules">
              <thead><tr><th>ID</th><th>Check</th><th>Severity</th><th>Platforms</th><th>Benchmark area</th></tr></thead>
              <tbody>{RULES.filter(r => r.category === c).map(r => <tr key={r.id}><td className="mono small">{r.id}</td><td><b>{r.title}</b><div className="small muted">{r.rationale}</div></td><td><Sev s={r.severity} /></td><td className="small">{r.platforms.join(', ')}</td><td className="small">{r.ref}</td></tr>)}</tbody>
            </table>
          </div>
        </div>
      ))}

      <h2 id="limits">6. Known limits</h2>
      <ul>
        <li>The audit reads configuration only. It cannot see software versions against advisories, SSH key sizes or runtime state (<code>show ip ssh</code>, interface counters).</li>
        <li>IPv6 ACLs are listed by name but not analysed for shadowing.</li>
        <li>Remediation scripts use the defaults on the <Link href="/settings">Settings</Link> page (management subnets, NTP and syslog servers). Review them, apply in a change window, and keep the <code>reload in</code> safety net on remote devices.</li>
      </ul>
    </section>
  )
}
