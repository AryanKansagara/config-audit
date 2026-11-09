// node scripts/qa-sync.mjs : signs up a throwaway account, round-trips an audit and a snapshot through the same tables the app syncs to, then deletes the account
import { readFileSync } from 'node:fs'
import { createClient } from '@supabase/supabase-js'
const env = Object.fromEntries(readFileSync(new URL('../.env', import.meta.url), 'utf8').split('\n').filter(l => l.includes('=') && !l.startsWith('#')).map(l => l.split('=')))
const sb = createClient(env.VITE_SUPABASE_URL, env.VITE_SUPABASE_PUBLISHABLE_KEY, { auth: { persistSession: false } })
const email = `qa-config-audit-${Date.now()}@example.com`, password = 'qa-' + Math.random().toString(36).slice(2) + 'X9!'
const ok = (label, r) => { if (r.error) { console.log('FAIL', label, r.error.message); process.exitCode = 1 } else console.log('ok  ', label) }
const up = await sb.auth.signUp({ email, password }); ok('sign up ' + email, up)
if (!up.data.session) ok('sign in', await sb.auth.signInWithPassword({ email, password }))
const id = crypto.randomUUID(), vid = crypto.randomUUID()
const project = { id, name: 'QA audit', devices: [{ id: 'd1', hostname: 'QA-RTR', platform: 'ios' }], waivers: {}, settings: {} }
ok('upsert audit', await sb.from('projects').upsert({ id, app: 'config-audit', name: 'QA audit', data: { project, dataset: { d1: 'hostname QA-RTR\nline vty 0 4\n transport input telnet\nend' } }, updated_at: new Date().toISOString() }))
ok('insert snapshot', await sb.from('project_versions').insert({ id: vid, project_id: id, label: 'QA snapshot', data: { id: vid, label: 'QA snapshot', at: Date.now(), score: 42, devices: [] } }))
const rows = await sb.from('projects').select('id,name,data').eq('app', 'config-audit'); ok('read back', rows)
console.log(rows.data?.length === 1 && rows.data[0].data.dataset.d1.includes('transport input telnet') ? 'ok   round trip matches' : 'FAIL round trip')
const vs = await sb.from('project_versions').select('id,data').in('project_id', [id]); console.log(vs.data?.length === 1 && vs.data[0].data.score === 42 ? 'ok   snapshot round trip' : 'FAIL snapshot')
ok('delete account', await sb.rpc('delete_my_account'))
const after = await sb.auth.signInWithPassword({ email, password }); console.log(after.error ? 'ok   account gone (' + after.error.message + ')' : 'FAIL account still exists')
