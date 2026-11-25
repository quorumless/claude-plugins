import type { EngineInterface as $, Register } from 'claude-code'

import { allowedNames, commitRange, ENV_FILES, findGitSend, type Mode, parseEnv, parseVault, quote, redact, rehydrate, replayable, ruleOf, scrubKnown } from './redact.ts'
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
  const raw = await $.fs.read(file).catch(() => '')
  const entries = parseVault(raw)
  const allowed = allowedNames(raw)
  return {
    entries,
    allowed,
    byName: new Map(entries.map(e => [e.name, e.value])),
    // exact-match scrub uses hash-named, replayable entries only; keyword/lone finds and legacy
    // SECRET_<stamp>_n names hold most of the false positives
    known: new Map(entries.filter(e => /^SECRET_[0-9a-f]{10}$/.test(e.name) && !allowed.has(e.name) && replayable(e.value, e.note))
      .map(e => [e.value, e.name])),
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

// append-only (O_APPEND) under umask 077: no lost writes between sessions, never world-readable
const append = async ($: $, lines: string) => {
  const { dir, file } = await paths($)
  try {
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

// secret-looking values in the cwd's .env files join the vault, so a bare `echo $TOKEN` is masked
// too: no keyword rule sees a value with no label next to it
const syncEnv = async ($: $) => {
  const cwd = await $.session.cwd()
  // a value first seen by a keyword rule gets an env line too, so it is replayed from now on
  const have = new Set((await load($)).known.keys())
  let lines = ''
  for (const f of ENV_FILES) {
    for (const { name, value } of parseEnv(await $.fs.read(`${cwd}/${f}`).catch(() => ''))) {
      if (have.has(value)) continue
      have.add(value)
      lines += `${await hashName(value)}=${quote(value)} # env ${f}:${name}\n`
    }
  }
  if (lines) await append($, lines)
}

// redacts text, appending new values to the vault; undefined when nothing was found
const guard = async ($: $, text: string, mode: Mode, source: string) => {
  await syncEnv($)
  const vault = await load($)
  const scrubbed = scrubKnown(text, vault.known)

  // redact's callback is sync, so hash every candidate up front
  const names = new Map<string, string>()
  redact(scrubbed, v => { names.set(v, ''); return 'SECRET_tmp' }, mode)
  for (const v of names.keys()) names.set(v, await hashName(v))
  // a value the first pass didn't see is left alone rather than masked under a name nothing restores
  const result = redact(scrubbed, v => {
    const n = names.get(v)
    return n && !vault.allowed.has(n) ? n : undefined
  }, mode)

  const fresh = result.found.filter(f => !vault.byName.has(f.name))
  if (fresh.length > 0) {
    await append($, fresh.map(f => `${f.name}=${quote(f.value)} # ${f.rule} ${source}\n`).join(''))
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
// cd X && git ..., or git -C X ...
const gitDir = (command: string, dir: string | undefined, cwd: string) => {
  const c = dir ?? command.match(/^\s*cd\s+(\S+)\s*&&/)?.[1]
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
    await $.command.register({
      name: 'secret',
      description: 'Copy a masked secret to the clipboard (no args: list them); forget drops one from the vault, allow stops masking that value, keep masks it everywhere',
      argumentHint: '[SECRET_name | forget|allow|keep SECRET_name]',
    })
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

    const vault = await load($)
    const { byName } = vault
    const used = (s: string) => [...new Set([...s.matchAll(/\$\{?(SECRET_\w+?)\}?(?!\w)/g)].map(m => m[1] ?? ''))]
      .filter(n => byName.has(n))
    // a keyword/lone find the model hands to a tool is about to be printed or written to disk, so from
    // here on it is masked wherever it shows up, not only where a rule sees it
    const promote = async (names: string[]) => {
      let lines = ''
      for (const n of names) {
        const v = byName.get(n) ?? ''
        if (vault.known.has(v) || vault.allowed.has(n)) continue
        lines += `${/^SECRET_[0-9a-f]{10}$/.test(n) ? n : await hashName(v)}=${quote(v)} # manual rehydrated\n`
      }
      if (lines) await append($, lines)
    }

    if (e.tool === 'Bash') {
      if (enabled && findGitSend(e.command)) {
        const verdict = await gitCheck($, e.command)
        if (verdict) return { deny: verdict }
      }

      const names = used(e.command)
      if (names.length === 0) return next(e)
      if (enabled && NETWORK.test(e.command)) {
        const answer = await $.ui.ask(
          `secret-guard: this command sends ${names.join(', ')} over the network:\n${e.command.slice(0, 300)}`,
          ['Allow', 'Deny'],
        ).catch(() => 'Deny') // dismissed, or a -p run with no one to ask
        if (answer !== 'Allow') return { deny: `secret-guard: user denied sending ${names.join(', ')}` }
      }
      await promote(names)
      // exported for this one command; real values never enter the transcript
      const exports = names.map(n => `export ${n}=${quote(byName.get(n) ?? '')};`).join(' ')
      return next({ ...e, command: `${exports}\n${e.command}` })
    }

    if (e.tool === 'Write') {
      await promote(used(e.content))
      return next({ ...e, content: rehydrate(e.content, byName) })
    }
    if (e.tool === 'Edit') {
      await promote(used(e.old_string + e.new_string))
      return next({ ...e, old_string: rehydrate(e.old_string, byName), new_string: rehydrate(e.new_string, byName) })
    }
    if (e.tool === 'NotebookEdit') {
      await promote(used(e.new_source))
      return next({ ...e, new_source: rehydrate(e.new_source, byName) })
    }
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
  // /secret forget|allow|keep <name>: a tombstone, allow or manual line appended to the vault; only from the
  // person's own prompt, so nothing the model drives can unmask a value. keep re-arms a real secret a
  // keyword/lone rule found, so it is masked everywhere
  on('command.run', { command: 'secret' }, async ($, e) => {
    const { entries } = await load($)
    const [verb = '', target = ''] = e.args.trim().split(/\s+/)
    if (verb === 'forget' || verb === 'allow' || verb === 'keep') {
      const n = target.replace(/^\$/, '')
      if (e.origin.kind !== 'composer') return { text: `/secret ${verb} only runs when you type it.` }
      if (verb === 'keep') {
        const kept = entries.find(x => x.name === n)
        if (!kept) return { text: `No ${n || 'name'} to keep. Run /secret to list names.` }
        // legacy SECRET_<stamp>_n names are never replayed, so the value moves to its hash name
        const name = /^SECRET_[0-9a-f]{10}$/.test(n) ? n : await hashName(kept.value)
        await append($, `${name}=${quote(kept.value)} # manual kept\n`)
        return { text: `Kept ${name}: it is masked wherever it shows up.` }
      }
      if (!/^SECRET_[0-9a-f]{10}$/.test(n) || (verb === 'forget' && !entries.some(x => x.name === n))) {
        return { text: `No ${n || 'name'} to ${verb}. Run /secret to list names.` }
      }
      await append($, `#${verb} ${n}\n`)
      return { text: verb === 'forget' ? `Forgot ${n}: it is no longer masked or restored.` : `Allowed ${n}: that value is never masked again.` }
    }
    const name = e.args.trim().replace(/^\$/, '')
    if (!name) {
      const rows = entries.map(x => `${x.name}  ${x.value.length} chars  ${x.note}`)
      return { text: rows.length ? rows.join('\n') : 'Vault is empty.' }
    }
    const entry = entries.find(x => x.name === name)
    if (!entry) return { text: `No ${name} in the vault. Run /secret to list names.` }
    // the module has no `process`, so the shell picks: pbcopy on macOS, xclip elsewhere
    const ran = await $.process.run(
      ['sh', '-c', 'if [ "$(uname -s)" = Darwin ]; then pbcopy; else xclip -selection clipboard; fi'],
      { stdin: entry.value },
    )
    return { text: ran.exitCode === 0 ? `Copied ${name} (${entry.value.length} chars) to the clipboard.` : `Clipboard copy failed (exit ${ran.exitCode}).` }
  })
}

// asks before a commit/push whose added lines hold a replayable vault value or a high-confidence secret
const gitCheck = async ($: $, command: string) => {
  const send = findGitSend(command)
  if (!send) return undefined
  const dir = gitDir(command, send.dir, await $.session.cwd())
  const { kind } = send
  const range = kind === 'push' ? ['@{upstream}..HEAD'] : send.cz ? ['--cached'] : commitRange(send.args)
  const diff = await $.process.run(['git', '-C', dir, 'diff', '--unified=0', ...range])
  if (diff.exitCode !== 0) {
    if (kind === 'push') return undefined // no upstream yet, not a repo: let git itself answer
    // a commit we can't inspect is not a clean one
    const answer = await $.ui.ask(
      `secret-guard: could not check this commit for secrets (git diff exit ${diff.exitCode}). Commit anyway?`,
      ['Allow', 'Deny'],
    ).catch(() => 'Deny')
    return answer === 'Allow' ? undefined : 'secret-guard: user denied a commit that could not be checked for secrets.'
  }

  // added lines, each with its file:line
  const added: string[] = []
  const where: string[] = []
  let file = ''
  let ln = 0
  for (const l of diff.stdout.split('\n')) {
    if (l.startsWith('+++ ')) file = l.slice(4).replace(/^b\//, '')
    else if (l.startsWith('@@')) ln = Number(l.match(/\+(\d+)/)?.[1] ?? 0)
    else if (l.startsWith('+')) { added.push(l.slice(1)); where.push(`${file}:${ln++}`) }
  }
  const text = added.join('\n')
  const at = (v: string) => where[text.slice(0, Math.max(0, text.indexOf(v))).split('\n').length - 1] ?? '?'

  const hits = new Map<string, { value: string; rule: string }>()
  const { entries, known, allowed } = await load($)
  for (const [value, name] of known) {
    if (scrubKnown(text, new Map([[value, name]])) !== text) hits.set(name, { value, rule: ruleOf(entries.find(e => e.name === name)?.note ?? '') })
  }
  for (const f of redact(text, v => v, 'high').found) {
    const name = await hashName(f.value)
    if (!allowed.has(name)) hits.set(name, { value: f.value, rule: f.rule })
  }
  // a key id alone is an identifier, not a credential
  const secret = [...hits.values()].some(h => h.rule === 'aws-secret' || h.rule === 'aws-pair')
  const list = [...hits].filter(([, h]) => secret || h.rule !== 'aws-key-id').map(([n, h]) => `$${n} (${at(h.value)})`).join(', ')
  if (!list) return undefined

  const answer = await $.ui.ask(`secret-guard: this ${kind} adds ${list}. ${kind === 'push' ? 'Push' : 'Commit'} anyway?`, ['Allow', 'Deny'])
    .catch(() => 'Deny')
  if (answer === 'Allow') return undefined
  return `secret-guard: user denied the ${kind}, the changes contain ${list}. ` +
    `Move them to .env/sops (encrypted) and reference them from there.`
}
