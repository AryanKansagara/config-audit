import { useMemo, useState } from 'react'
import { auditText, type Finding } from './engine/audit.ts'
import { lineDiff } from './engine/fleet.ts'
import { maskSecrets } from './engine/mask.ts'
import { RULES } from './engine/rules.ts'
import { BRANCH } from './engine/samples.ts'
import { applyBlocks } from './engine/simulate.ts'
import { ConfigView, ScoreRing, Sev, SevBar, sevCounts } from './components.tsx'
import { Link } from './ui.tsx'

const START = maskSecrets(BRANCH).text

const fixText = (f: Finding) => (f.fix?.apply ?? []).flatMap(b => [...b.parents.map((p, i) => ' '.repeat(i) + p), ...b.cmds.map(c => ' '.repeat(b.parents.length) + c), ...(b.parents.length ? ['exit'] : [])]).join('\n')

function Hero() {
  const [text, setText] = useState(START)
  const [selected, setSelected] = useState<string | null>(null)
  const [last, setLast] = useState<Finding | null>(null)
  const [added, setAdded] = useState<Set<number>>(new Set())
  const a = useMemo(() => auditText(text), [text])
  const open = a.findings
  const sel = open.find(f => f.key === selected) ?? null

  const apply = (fs: Finding[]) => {
    const next = applyBlocks(text, fs.flatMap(f => f.fix?.apply ?? []))
    const plus = new Set(lineDiff(text.split('\n'), next.split('\n')).filter(d => d.op === '+').map(d => d.nb!))
    setAdded(plus)
    setText(next)
    setLast(fs.length === 1 ? fs[0] : { ...fs[0], title: `${fs.length} critical findings`, fix: { apply: fs.flatMap(f => f.fix?.apply ?? []), rollback: [] } })
    setSelected(null)
  }
  const crit = open.filter(f => f.severity === 'critical' && f.fix)

  return (
    <div className="hero-demo" aria-label="Live demo on a synthetic branch router">
      <div className="demo-bar">
        <span className="demo-dots" aria-hidden="true"><i /><i /><i /></span>
        <span className="mono small">BR-RTR-01 · show running-config · synthetic</span>
        <span className="demo-live"><i aria-hidden="true" />Live parser</span>
      </div>
      <div className="demo-grid">
        <ConfigView text={text} findings={open} selected={selected} onSelect={f => setSelected(f.key)} added={added} maxHeight={430} />
        <aside className="demo-side">
          <div className="demo-score">
            <ScoreRing score={a.score} grade={a.grade} size={112} />
            <div>
              <div className="eyebrow light">Hardening score</div>
              <strong className="demo-count">{open.length} open findings</strong>
              <SevBar counts={sevCounts(open)} />
              <div className="row gap-sm wrap" style={{ marginTop: 10 }}>
                {crit.length > 0 && <button type="button" className="btn primary sm" onClick={() => apply(crit)}>Fix {crit.length} critical</button>}
                {text !== START && <button type="button" className="btn on-dark sm" onClick={() => { setText(START); setAdded(new Set()); setLast(null); setSelected(null) }}>Reset</button>}
              </div>
            </div>
          </div>
          {sel ? (
            <div className="demo-detail">
              <div className="row between"><Sev s={sel.severity} /><span className="mono small dim">{sel.rule} · line {sel.line ?? '—'}</span></div>
              <h3>{sel.title}</h3>
              <p className="small dim">{sel.detail}</p>
              <pre className="demo-cmds"><code>{fixText(sel)}</code></pre>
              <div className="row gap-sm"><button type="button" className="btn primary sm" onClick={() => apply([sel])}>Fix</button><button type="button" className="btn on-dark sm" onClick={() => setSelected(null)}>Back</button></div>
            </div>
          ) : (
            <>
              {last && (
                <div className="demo-detail applied" aria-live="polite">
                  <div className="eyebrow light">Applied: {last.title}</div>
                  <pre className="demo-cmds"><code>{fixText(last)}</code></pre>
                </div>
              )}
              <ul className="demo-list">
                {open.slice(0, last ? 4 : 7).map(f => (
                  <li key={f.key}>
                    <button type="button" className="demo-item" onClick={() => setSelected(f.key)}>
                      <i className={`dot dot-${f.severity}`} aria-hidden="true" />
                      <span><strong>{f.title}</strong><small>{f.target === 'global' ? 'global' : f.target}</small></span>
                    </button>
                    {f.fix && <button type="button" className="btn ghost-dark xs" onClick={() => { setSelected(f.key); apply([f]) }} aria-label={`Fix: ${f.title}`}>Fix</button>}
                  </li>
                ))}
              </ul>
            </>
          )}
        </aside>
      </div>
    </div>
  )
}

/** Shadowing explained on the real core switch ACL: address coverage of lines 30 and 40 vs line 50. */
function AclViz() {
  const rows = [
    { n: '30', text: 'permit tcp 10.20.0.0 0.0.127.255 10.30.1.0 0.0.0.255 eq 22', from: 0, to: 50, kind: 'permit' },
    { n: '40', text: 'permit tcp 10.20.128.0 0.0.127.255 10.30.1.0 0.0.0.255 eq 22', from: 50, to: 100, kind: 'permit' },
    { n: '50', text: 'deny tcp 10.20.0.0 0.0.255.255 host 10.30.1.20 eq 22', from: 0, to: 100, kind: 'shadow' },
  ]
  return (
    <figure className="aclviz">
      <div className="aclviz-axis" aria-hidden="true"><span>10.20.0.0</span><span>10.20.128.0</span><span>10.20.255.255</span></div>
      {rows.map(r => (
        <div key={r.n} className="aclviz-row">
          <code className="mono small"><b>{r.n}</b> {r.text}</code>
          <div className="aclviz-track"><i className={`aclviz-${r.kind}`} style={{ left: `${r.from}%`, width: `${r.to - r.from}%` }} /></div>
        </div>
      ))}
      <figcaption className="small muted">Neither line 30 nor 40 covers line 50 alone. Together they permit every source it would deny, so the deny never fires. Config Audit subtracts address, port and protocol boxes to find this.</figcaption>
    </figure>
  )
}

export function Landing() {
  return (
    <>
      <section className="hero">
        <div className="hero-inner">
          <div className="hero-copy">
            <div className="eyebrow light">For network engineers before an audit or a security push</div>
            <h1>Turn a pile of running-configs into a hardening score and the exact fix commands.</h1>
            <p className="lead">Config Audit parses Cisco IOS, IOS XE, NX-OS and ASA configs as real parent/child blocks, runs {RULES.length} CIS and STIG style checks, finds shadowed ACL entries, and writes a per-device remediation script with rollback. Secrets are masked before anything is stored.</p>
            <div className="row gap wrap">
              <Link href="/app?sample=fleet" className="btn primary lg">Try the sample fleet</Link>
              <Link href="/app" className="btn on-dark lg">Audit your configs</Link>
            </div>
            <p className="hero-note small">Runs in your browser. No agent, no SSH, no upload. Click a finding on the right, then Fix.</p>
          </div>
          <Hero />
        </div>
      </section>

      <section className="strip" aria-label="At a glance">
        <div className="strip-inner">
          <div><strong>{RULES.length}</strong><span>hardening checks</span></div>
          <div><strong>4</strong><span>platforms: IOS, IOS XE, NX-OS, ASA</span></div>
          <div><strong>6-D</strong><span>ACL reasoning: protocol, addresses, ports, flags</span></div>
          <div><strong>0</strong><span>secrets stored: masked on import</span></div>
        </div>
      </section>

      <section className="band">
        <div className="wrap">
          <div className="section-head">
            <div className="eyebrow">Why not grep</div>
            <h2>Regex on lines fails on block context. This parser does not.</h2>
            <p className="muted">"transport input telnet" means nothing until you know which line block it sits in. Banners can contain text that looks like commands. An ACL entry can be dead because of two other entries. Config Audit reads the config the way IOS does: as a tree.</p>
          </div>
          <div className="features">
            <article className="feature"><h3>Hardening score</h3><p>AAA, SSH v2 and no telnet on VTYs, exec-timeout, access-class, type 7 and plain passwords, enable secret type 8/9, SNMP without ACLs, logging and NTP auth, unused services, banners, unused ports. Each check has a rationale and a fix.</p></article>
            <article className="feature"><h3>ACL cleanup</h3><p>Shadowed and redundant entries via interval and prefix reasoning on IPv4 extended ACLs, any/any permits, ACLs applied but never defined, ACLs and object-groups referenced nowhere.</p></article>
            <article className="feature"><h3>Remediation with rollback</h3><p>Config-mode commands grouped under the right parent (interface, line, router), shared ACLs defined once and before use, a reload-in safety net, and a matching rollback script.</p></article>
            <article className="feature"><h3>Fleet drift</h3><p>NTP servers, syslog hosts, VTY transport, timeouts, AAA lists and more, compared across every device with the majority value highlighted.</p></article>
            <article className="feature"><h3>Waivers that expire</h3><p>Accept a risk with a reason and an end date. The finding stops counting until the date passes, then comes back on its own.</p></article>
            <article className="feature"><h3>Snapshots and diffs</h3><p>Save each audit. Compare any two: fixed, new and regressed findings, score movement per device, and a config diff grouped by block.</p></article>
          </div>
        </div>
      </section>

      <section className="band alt">
        <div className="wrap split">
          <div>
            <div className="eyebrow">ACL reasoning</div>
            <h2>The deny you wrote is not the deny that runs.</h2>
            <p className="muted">On the sample core switch, entry 50 in SERVERS-IN is meant to block SSH to one server. It never matches. Each ACE becomes a set of boxes over protocol, source, destination, ports and the established flag, and earlier entries are subtracted from later ones until nothing is left.</p>
            <Link href="/app?sample=fleet&tab=acls" className="btn outline">See it on the sample</Link>
          </div>
          <AclViz />
        </div>
      </section>

      <section className="band">
        <div className="wrap">
          <div className="section-head">
            <div className="eyebrow">How it works</div>
            <h2>From show run to a signed-off report in one sitting</h2>
          </div>
          <ol className="steps">
            <li><strong>Collect</strong><span>Paste <code>show running-config</code>, drop files, a zip of an Oxidized or RANCID repo, or Ansible <code>ios_facts</code> JSON. <Link href="/docs">How to collect</Link>.</span></li>
            <li><strong>Mask and validate</strong><span>Platform is detected, secrets are replaced by their type and strength, and paging or truncation problems are reported with line numbers.</span></li>
            <li><strong>Audit</strong><span>Score per device and for the fleet, findings in the config tree, ACL analysis, inventory and drift.</span></li>
            <li><strong>Act</strong><span>Copy the remediation script, waive what you accept, print the report, export CSV, and snapshot it for next quarter.</span></li>
          </ol>
          <div className="cta">
            <h2>Start with your own configs</h2>
            <p className="muted">Nothing to install. Works offline after the first load. Sign in only if you want sync across machines.</p>
            <div className="row gap center-x wrap"><Link href="/app" className="btn primary lg">Open Config Audit</Link><Link href="/docs" className="btn outline lg">Collection guide</Link></div>
          </div>
        </div>
      </section>
    </>
  )
}
