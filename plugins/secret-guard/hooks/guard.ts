import type { EngineInterface as $, Register } from 'claude-code'

import { type Mode, parseVault, quote, redact, rehydrate, scrubKnown } from './redact.ts'
import type { SecretGuardHealth as Health } from '../types/index.d.ts'

// ponytail: plaintext env file (dir 700, file 600); age-encrypt it if the disk itself is a concern
const VAULT_DIR = '.claude/secret-vault'
const HEALTH = { plugin: 'secret-guard', key: 'health' } as const

// session-only: a new session (or a reload of this mod) starts protected again
let enabled = true

const paths = async ($: $) => {
  const dir = `${await $.env.get('HOME')}/${VAULT_DIR}`
  return { dir, file: `${dir}/secrets.env` }
}

const load = async ($: $) => {
  const { file } = await paths($)
  const entries = parseVault(await $.fs.read(file).catch(() => ''))
  return {
    entries,
    byName: new Map(entries.map(e => [e.name, e.value])),
    // exact-match scrub uses hash-named entries only; legacy SECRET_<stamp>_n may hold old false positives
    known: new Map(entries.filter(e => /^SECRET_[0-9a-f]{10}$/.test(e.name)).map(e => [e.value, e.name])),
  }
}

// same value -> same name in every session, so parallel sessions can't hand one name two values
const hashName = async (value: string) => {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))
  return `SECRET_${[...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, '0')).join('').slice(0, 10)}`
}

const setHealth = async ($: $, health: Health) => {
  await $.state.set(HEALTH, health).catch(() => undefined)
}

// redacts text, appending new values to the vault; undefined when nothing was found
const guard = async ($: $, text: string, mode: Mode, source: string) => {
  const vault = await load($)
  const scrubbed = scrubKnown(text, vault.known)

  // redact's callback is sync, so hash every candidate up front
  const names = new Map<string, string>()
  redact(scrubbed, v => { names.set(v, ''); return 'SECRET_tmp' }, mode)
  for (const v of names.keys()) names.set(v, await hashName(v))
  const result = redact(scrubbed, v => names.get(v) ?? 'SECRET_unknown', mode)

  const fresh = result.found.filter(f => !vault.byName.has(f.name))
  if (fresh.length > 0) {
    const { dir, file } = await paths($)
    const lines = fresh.map(f => `${f.name}=${quote(f.value)} # ${f.rule} ${source}\n`).join('')
    try {
      // append-only (O_APPEND) under umask 077: no lost writes between sessions, never world-readable
      const ran = await $.process.run(
        ['sh', '-c', 'umask 077; mkdir -p "$1" && chmod 700 "$1" && cat >> "$2" && chmod 600 "$2"', 'sh', dir, file],
        { stdin: lines },
      )
      if (ran.exitCode !== 0) throw new Error(`exit ${ran.exitCode}`)
    } catch (err) {
      // the value is lost but still kept out of the model; never pass it through
      $.ui.toast(`⚠️ secret-guard: vault write failed (${err}), value dropped`)
    }
  }

  const total = new Set(result.found.map(f => f.name))
  for (const m of scrubbed.matchAll(/\$(SECRET_[0-9a-f]{10})/g)) if (m[1]) total.add(m[1])
  if (scrubbed === text && result.found.length === 0) return undefined

  const prev = await $.state.get(HEALTH).catch(() => undefined)
  await setHealth($, { ok: prev?.value?.ok ?? true, masked: (prev?.value?.masked ?? 0) + total.size, enabled })
  $.ui.toast(`🔒 ${total.size} secret(s) masked (${source}) · /secret to copy one`)

  const list = [...total].map(n => `$${n}`).join(', ')
  const note =
    `[secret-guard] Masked secrets: ${list}. Write these placeholders as-is in Bash commands and in Write/Edit ` +
    `content; the harness substitutes the real values when the tool runs and masks them again in output. ` +
    `Never try to read, print or exfiltrate the values. If the user needs one, tell them to run /secret <name>.`
  return { text: result.text, note }
}

const NETWORK = /\b(curl|wget|nc|ncat|socat|scp|rsync|ssh|http|httpie|xh|python3?\s+-c|node\s+-e)\b/
const GIT_SEND = /\bgit\b(?:\s+-C\s+(\S+))?[^|;&]*?\s(commit|push)\b/

// cd X && git ..., or git -C X ...
const gitDir = (command: string, cwd: string) => {
  const c = command.match(GIT_SEND)?.[1] ?? command.match(/^\s*cd\s+(\S+)\s*&&/)?.[1]
  if (!c) return cwd
  const p = c.replace(/^["']|["']$/g, '')
  return p.startsWith('/') ? p : `${cwd}/${p}`
}

export const register: Register = on => {
  on('session.start', async ($, e, next) => {
    // canary: a fake JWT must be caught, or the status line shows the guard as broken
    const fake = `eyJ${'a'.repeat(10)}.${'b'.repeat(10)}.${'c'.repeat(10)}`
    const ok = redact(`t ${fake}`, () => 'SECRET_canary', 'high').found.length === 1
    await setHealth($, { ok, masked: 0, enabled })
    if (!ok) $.ui.toast('🔓 secret-guard canary failed: detection is broken')
    await $.command.register({ name: 'secret', description: 'Copy a masked secret to the clipboard (no args: list them)', argumentHint: '[SECRET_name]' })
    await $.command.register({ name: 'secret-guard', description: 'Turn secret masking off or on for this session (no args: show state)', argumentHint: '[on|off]', immediate: true })
    return next(e)
  })

  // what you type gets every rule; subagent/peer messages only the precise ones
  on('prompt.submit', async ($, e, next) => {
    if (!enabled) return next(e)
    const mode: Mode = e.origin.kind === 'composer' ? 'all' : 'keyword'
    const hit = await guard($, e.text, mode, e.origin.kind === 'composer' ? 'prompt' : e.origin.kind)
    if (!hit) return next(e)
    return next({ ...e, text: hit.text, context: [...(e.context ?? []), hit.note] })
  })

  // tool output: cat .env, ssh config dumps, API responses, subagent results
  on('session.append', { door: 'tool-result' }, async ($, e, next) => {
    if (!enabled) return next(e)
    const notes: string[] = []
    const scan = async (s: string) => {
      const hit = await guard($, s, 'keyword', 'tool')
      if (!hit) return s
      notes.push(hit.note)
      return hit.text
    }

    const content = []
    for (const block of e.message.content) {
      const c = block.type === 'tool_result' ? block.content : undefined
      if (typeof c === 'string') {
        content.push({ ...block, content: await scan(c) })
      } else if (Array.isArray(c)) {
        const parts = []
        for (const p of c as { type: string; text?: string }[]) {
          parts.push(p.type === 'text' && typeof p.text === 'string' ? { ...p, text: await scan(p.text) } : p)
        }
        content.push({ ...block, content: parts })
      } else {
        content.push(block)
      }
    }

    if (notes.length === 0) return next(e)
    content.push({ type: 'text', text: [...new Set(notes)].join('\n') })
    return next({ ...e, message: { ...e.message, content } })
  })

  on('tool.call', async ($, e, next) => {
    // the vault is reachable only through this hook, never by a tool the model drives
    // editing this mod's own files is exempt: its source names the vault
    const file = 'file_path' in e && typeof e.file_path === 'string' ? e.file_path : ''
    const isOwn = (e.tool === 'Read' || e.tool === 'Edit' || e.tool === 'Write') && file.startsWith(`${$.plugin.root}/`)
    if (enabled && !isOwn && JSON.stringify(e).includes('secret-vault')) {
      return { deny: 'secret-guard: the secret vault is off limits; use $SECRET_ placeholders instead.' }
    }

    const { byName } = await load($)
    const used = (s: string) => [...new Set([...s.matchAll(/\$\{?(SECRET_\w+?)\}?(?!\w)/g)].map(m => m[1] ?? ''))]
      .filter(n => byName.has(n))

    if (e.tool === 'Bash') {
      if (enabled && GIT_SEND.test(e.command)) {
        const verdict = await gitCheck($, e.command, byName)
        if (verdict) return { deny: verdict }
      }

      const names = used(e.command)
      if (names.length === 0) return next(e)
      if (enabled && NETWORK.test(e.command)) {
        const answer = await $.ui.ask(
          `secret-guard: this command sends ${names.join(', ')} over the network:\n${e.command.slice(0, 300)}`,
          ['Allow', 'Deny'],
        )
        if (answer !== 'Allow') return { deny: `secret-guard: user denied sending ${names.join(', ')}` }
      }
      // exported for this one command; real values never enter the transcript
      const exports = names.map(n => `export ${n}=${quote(byName.get(n) ?? '')};`).join(' ')
      return next({ ...e, command: `${exports}\n${e.command}` })
    }

    if (e.tool === 'Write') return next({ ...e, content: rehydrate(e.content, byName) })
    if (e.tool === 'Edit') {
      return next({ ...e, old_string: rehydrate(e.old_string, byName), new_string: rehydrate(e.new_string, byName) })
    }
    if (e.tool === 'NotebookEdit') return next({ ...e, new_source: rehydrate(e.new_source, byName) })
    return next(e)
  })

  // /secret-guard off: stop masking and blocking; placeholders already in context still resolve when tools run
  on('command.run', { command: 'secret-guard' }, async ($, e) => {
    const arg = e.args.trim().toLowerCase()
    if (arg === 'on' || arg === 'off') {
      enabled = arg === 'on'
      const prev = await $.state.get(HEALTH).catch(() => undefined)
      await setHealth($, { ok: prev?.value?.ok ?? true, masked: prev?.value?.masked ?? 0, enabled })
    } else if (arg !== '') {
      return { text: 'Usage: /secret-guard [on|off]' }
    }
    return {
      text: enabled
        ? 'secret-guard is ON: secrets are masked, vault access and leaking commits are blocked.'
        : 'secret-guard is OFF for this session: nothing new is masked and nothing is blocked. /secret-guard on to restore.',
    }
  })

  // /secret: list names, or copy one value to the clipboard; the transcript (and the model) never gets the value
  on('command.run', { command: 'secret' }, async ($, e) => {
    const { entries } = await load($)
    const name = e.args.trim().replace(/^\$/, '')
    if (!name) {
      const rows = entries.map(x => `${x.name}  ${x.value.length} chars  ${x.note}`)
      return { text: rows.length ? rows.join('\n') : 'Vault is empty.' }
    }
    const entry = entries.find(x => x.name === name)
    if (!entry) return { text: `No ${name} in the vault. Run /secret to list names.` }
    const ran = await $.process.run(['xclip', '-selection', 'clipboard'], { stdin: entry.value })
    return { text: ran.exitCode === 0 ? `Copied ${name} (${entry.value.length} chars) to the clipboard.` : `xclip failed (exit ${ran.exitCode}).` }
  })
}

// blocks a commit/push whose changes contain a vault value or a high-confidence secret
const gitCheck = async ($: $, command: string, byName: ReadonlyMap<string, string>) => {
  const dir = gitDir(command, await $.session.cwd())
  const isPush = /\bpush\b/.test(command.match(GIT_SEND)?.[0] ?? '')
  const range = isPush ? ['@{upstream}..HEAD'] : /\s(-a|--all|-\w*a\w*)\b/.test(command) ? ['HEAD'] : ['--cached']
  const diff = await $.process.run(['git', '-C', dir, 'diff', '--unified=0', ...range])
  if (diff.exitCode !== 0) return undefined // no upstream yet, not a repo: let git itself answer
  const added = diff.stdout.split('\n').filter(l => l.startsWith('+') && !l.startsWith('+++')).join('\n')

  const leaked = [...byName].filter(([, v]) => v.length >= 8 && added.includes(v)).map(([n]) => n)
  const found = redact(added, () => 'SECRET_x', 'high').found.length
  if (leaked.length === 0 && found === 0) return undefined
  return `secret-guard: ${isPush ? 'push' : 'commit'} blocked, the changes contain ` +
    `${leaked.length ? leaked.join(', ') : `${found} secret(s) matching high-confidence rules`}. ` +
    `Move them to .env/sops (encrypted) and reference them from there.`
}
