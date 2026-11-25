// Pure detection/redaction, no engine imports, so it runs under plain node for the self-check.
// Rules ported from gitleaks config/gitleaks.toml and detect-secrets keyword.py.

const entropy = (s: string) => {
  const m = new Map<string, number>()
  for (const c of s) m.set(c, (m.get(c) ?? 0) + 1)
  let e = 0
  for (const n of m.values()) { const p = n / s.length; e -= p * Math.log2(p) }
  return e
}
const classes = (s: string) => [/[a-z]/, /[A-Z]/, /\d/, /[^\w]/].filter(r => r.test(s)).length

// $VAR, ${VAR}, {{tpl}}, sops ENC[..], <placeholder>, ****, changeme, example...
const PLACEHOLDER = /^(?:\$\{?[A-Za-z_]\w*\}?|\{\{.*\}\}|ENC\[.*|<[^>]+>|\*+|x{4,}|changeme|example\w*)$/i
// docs and templates: YOUR_TOKEN_HERE, changeme, <token>, xxxx (case-insensitive substring)
const STOPWORD = /example|your_|_here|changeme|placeholder|dummy|sample|redacted|xxxx|[<>]/i
const AWS_EXAMPLE = /EXAMPLE(?:KEY)?$/
const CIPHER = new Set(['SHA', 'SHA256', 'SHA384', 'GCM', 'AES128', 'AES256', 'CBC', 'POLY1305', 'CHACHA20', 'ECDHE', 'ECDSA', 'RSA'])
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
// getToken(req), os.environ[, self.token, https://..., /run/secrets/x
const CODE = /[()[\]{}<>]|:\/\/|^[/~.$%@]|^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+$/

// keyword value: not a placeholder, code or plain word (incl. Polish letters), and looks random
// lowercase a/b/c paths and file names; mixed-case base64 with / stays plausible
const PATHLIKE = /^[a-z0-9_.-]*(?:\/[a-z0-9_.-]+)+\/?$|\.[a-z]{1,5}$/
// keyword value, gitleaks-style: not a placeholder, code, ARN, path, grep line number or plain word,
// and random enough (entropy >= 3.5, or 3 char classes over 12+ chars)
const plausible = (v: string) =>
  !PLACEHOLDER.test(v) && !CODE.test(v) && !STOPWORD.test(v) && !/^arn:/i.test(v) && !/^\d+:/.test(v) &&
  !PATHLIKE.test(v) && !/^[\p{L}_.-]+$/u.test(v) && !UUID.test(v) &&
  (entropy(v) >= 3.5 || (classes(v) >= 3 && v.length >= 12))

// high: a known format, safe on any text. keyword: a label + value, only where false positives are cheap
export type Mode = 'high' | 'keyword' | 'all'
// id is written to the vault note and decides whether an entry is replayed (see replayable)
type Rule = { id: string; re: RegExp; tier: 'high' | 'keyword'; check?: (v: string) => boolean }

// value is the first capture group when present, else the whole match
const RULES: readonly Rule[] = [
  // needs its END line: a header mentioned in prose used to swallow the rest of the text
  { id: 'pem', tier: 'high', re: /-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----(?:(?!-----BEGIN)[\s\S]){0,20000}?-----END[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----/g },
  { id: 'jwt', tier: 'high', re: /\beyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]{8,}/g }, // JWT: HA, n8n, homelable, OVH
  { id: 'cloudflare', tier: 'high', re: /\bcf(?:k|ut|at)_[A-Za-z0-9]{40,}/g }, // Cloudflare
  { id: 'grafana', tier: 'high', re: /\bglsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}\b/g }, // Grafana service account
  { id: 'telegram', tier: 'high', re: /\b\d{8,10}:AA[\w-]{33}\b/g }, // Telegram bot (not <account id>:AWSReservedSSO_...)
  // AWS: labelled secret/session token (aws sts JSON, CloudTrail, credentials files), STS token by its
  // prefix, and a bare 40-char secret on the line of a key id; docs examples end in EXAMPLE(KEY)
  {
    id: 'aws-secret', tier: 'high', check: v => !AWS_EXAMPLE.test(v),
    re: /(?:aws_?)?secret_?access_?key["']?[ \t]*[:=][ \t]*["']?([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+=])/gi,
  },
  { id: 'aws-session', tier: 'high', re: /session_?token["']?[ \t]*[:=][ \t]*["']?([A-Za-z0-9/+=]{100,})/gi },
  { id: 'sts-token', tier: 'high', re: /\b(?:IQoJb3JpZ2lu|FwoGZXIvYXdz)[A-Za-z0-9/+=]{100,}/g },
  {
    id: 'aws-pair', tier: 'high', check: v => !AWS_EXAMPLE.test(v) && /[a-z]/.test(v) && /[A-Z]/.test(v),
    re: /\b(?:AKIA|ASIA)[A-Z2-7]{16}\b[^\n]{0,200}?[ \t]([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+=])/g,
  },
  { id: 'aws-key-id', tier: 'high', re: /\b(?:AKIA|ASIA)[A-Z2-7]{16}\b/g, check: v => !AWS_EXAMPLE.test(v) }, // AWS key id
  { id: 'age', tier: 'high', re: /\bAGE-SECRET-KEY-1[A-Z0-9]{58}\b/g }, // age identity (sops)
  // GitLab routable PAT before the generic prefix rule, which stops at the . and leaves the tail visible
  { id: 'gitlab-pat', tier: 'high', re: /\bglpat-[0-9A-Za-z_-]{27,300}\.[0-9a-z]{2}[0-9a-z]{7}\b/g },
  // ponytail: a dashed lowercase name with short words (sk-backup-replication-eu-central-1) is a resource
  // name, not a token; real tokens carry uppercase or a long random run
  {
    id: 'prefix', tier: 'high', re: /\b(?:sk-ant-|sk-|ghp_|gho_|github_pat_|glpat-|xox[bpa]-)[\w-]{20,}/g,
    check: v => !/^[a-z]+-(?:[a-z0-9]{1,12}-)*[a-z0-9]{1,12}$/.test(v),
  },
  { id: 'url', tier: 'high', re: /\b[a-z][a-z0-9+.-]{1,20}:\/\/[^\s:@/]{1,64}:([^\s@/]{3,128})@/gi, check: v => !PLACEHOLDER.test(v) }, // scheme://user:pass@
  // case-sensitive, same line, token charset: "examples/basic\n.spacelift/config.yml" is a listing, not a header
  {
    id: 'bearer', tier: 'high', re: /\b(?:Bearer|Basic)[ \t]+([\w.~+/=-]{16,})/g,
    check: v => /^[\w.~+/=-]{16,}$/.test(v) && !PLACEHOLDER.test(v) && !STOPWORD.test(v) && !/^[./]|\.[a-z]{1,5}$/.test(v),
  },
  // licence keys: some segment mixes letters and digits and isn't a TLS cipher-suite token
  {
    id: 'licence', tier: 'high', re: /\b[A-Z0-9]{5,8}(?:-[A-Z0-9]{5,8}){3,}\b/g,
    check: v => !UUID.test(v) && v.split('-').some(x => /\d/.test(x) && /[A-Z]/.test(x) && !CIPHER.has(x)),
  },
  {
    // keyword must stand alone or between separators: CF_API_TOKEN yes, author / tokenizer / bypass no.
    // the key starts a line or follows whitespace, a quote, { ( or , (never a file name in grep output),
    // and doesn't end in _arn/_id/_name/... (secret_arn = "arn:..." names a secret, it isn't one)
    id: 'keyword',
    tier: 'keyword',
    // a $SECRET_x / ${SECRET_x} placeholder is never the key: masking one value must not cascade
    re: /(?<=^|[\s"'{(,])(?<!\$\{)(?:[\w.-]{0,30}?[_.-])?(?:passw(?:or)?d|passwd|pwd|passphrase|has[lł][oa]|secret|token|api[_-]?key|auth[_-]?(?:token|key)|credentials?|creds|master[_-]?key|private[_-]?key)(?:[_.-][\w.-]{0,20})?(?![\p{L}\d])(?<!arn|id|_name|_version|_ref|_path|_file|_type|_charset|_rate|_method|_url)["']?[ \t]*(?::=|=>|[:=])[ \t]*["'`]?([^\s"'`,;]{6,200})/giu,
    check: plausible,
  },
]

// whole prompt is one opaque string, e.g. a pasted password or API token
const LONE = /^\s*(\S{12,})\s*$/
// pasted identifiers, not secrets: git SHA / hex digest, UUID, ULID, ARN, sha256: image digest
const IDENT = /^(?:[0-9a-f]{7,64}|[0-9A-HJKMNP-TV-Z]{26}|arn:\S+|\S*@?sha256:[0-9a-f]{64})$/i
const isOpaque = (s: string) =>
  !UUID.test(s) && !IDENT.test(s) &&
  !/^(https?:|\/|~|\.|@|\$)/.test(s) && !/\.\w{1,5}$/.test(s) && !/@[\w-]+\./.test(s) && !PLACEHOLDER.test(s) &&
  !/^[A-Za-z0-9]+(?:[-_./:][A-Za-z0-9]+)+$/.test(s) && // Qwen3.5-397B-A17B, moonshotai/kimi-k3, GENERIC_OPEN_AI
  (classes(s) >= 3 || (s.length >= 20 && entropy(s) >= 3.5))

export type Found = { name: string; value: string; rule: string }

// nameFor maps a value to its vault name (existing or new), or undefined to leave it (an allowed value)
export const redact = (
  text: string,
  nameFor: (value: string) => string | undefined,
  mode: Mode = 'all',
): { text: string; found: Found[] } => {
  const found: Found[] = []
  const seen = new Set<string>() // not found.some(): 50k distinct finds on one line made that quadratic
  const stash = (value: string, rule: string) => {
    const name = nameFor(value)
    if (!name) return value
    if (!seen.has(name)) { seen.add(name); found.push({ name, value, rule }) }
    return `$${name}`
  }

  const lone = mode === 'all' ? text.match(LONE)?.[1] : undefined
  if (lone && isOpaque(lone)) {
    return { text: text.replace(lone, stash(lone, 'lone')), found }
  }

  let out = text
  for (const { id, re, tier, check } of RULES) {
    if (mode === 'high' && tier !== 'high') continue
    out = out.replace(re, (whole: string, ...groups: unknown[]) => {
      const value = typeof groups[0] === 'string' && groups[0] !== '' ? groups[0] : whole
      if (value.startsWith('$SECRET_') || (check && !check(value))) return whole
      const at = whole.lastIndexOf(value) // value ends the match; lastIndexOf so a key containing it is left alone
      return whole.slice(0, at) + stash(value, id) + whole.slice(at + value.length)
    })
  }
  return { text: out, found }
}

// known vault values anywhere in text, longest first so one value inside another can't split it;
// only as a whole token: "password" in a vault never masks "passwords"
const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
export const scrubKnown = (text: string, known: ReadonlyMap<string, string>): string => {
  let out = text
  for (const [value, name] of [...known].sort((a, b) => b[0].length - a[0].length)) {
    if (value.length < 8 || !out.includes(value)) continue
    // a boundary only on a side where the value itself is a word char: "-key=x-" still matches inside "a-key=x-b"
    const before = /^\w/.test(value) ? '(?<![A-Za-z0-9_])' : ''
    const after = /\w$/.test(value) ? '(?![A-Za-z0-9_])' : ''
    out = out.replace(new RegExp(`${before}${escapeRe(value)}${after}`, 'g'), () => `$${name}`)
  }
  return out
}

// vault notes before rules had ids: "rule<index>" in this order
const LEGACY = ['pem', 'jwt', 'cloudflare', 'grafana', 'telegram', 'aws-key-id', 'age', 'prefix', 'url', 'bearer', 'licence']

// replayed anywhere as a substring: .env and manual entries, and high-tier finds that still pass
// today's rule. keyword and lone finds stay where they were seen; most of them were false positives
// the rule id (or env/manual/keyword/lone) a vault note starts with
export const ruleOf = (note: string) => {
  const tag = note.split(' ')[0] ?? ''
  return /^rule\d+$/.test(tag) ? LEGACY[Number(tag.slice(4))] ?? tag : tag
}

export const replayable = (value: string, note: string): boolean => {
  const id = ruleOf(note)
  if (id === 'env' || id === 'manual') return true
  const rule = RULES.find(r => r.id === id && r.tier === 'high')
  if (!rule || (rule.check && !rule.check(value))) return false
  // a captured value (url password, bearer token) was checked above; the rest must still match whole
  return /\((?!\?)/.test(rule.re.source) || new RegExp(`^(?:${rule.re.source})$`, rule.re.flags.replace('g', '')).test(value)
}

// $SECRET_x / ${SECRET_x} back to values; unknown names left as typed
export const rehydrate = (text: string, byName: ReadonlyMap<string, string>): string =>
  text.replace(/\$(?:\{(SECRET_\w+)\}|(SECRET_\w+))/g, (whole, braced?: string, bare?: string) => byName.get(braced ?? bare ?? '') ?? whole)

// .env files the guard learns values from: whatever is in them is masked wherever it shows up,
// labelled or not (echo $TOKEN prints a bare value no keyword rule can see)
export const ENV_FILES = ['.env', '.env.local', '.env.development', '.env.production'] as const
const ENV_SECRET_NAME = /(?:^|_)(?:passw(?:or)?d|passwd|pwd|secret|token|api_?key|auth|credentials?|creds|private_?key|master_?key)(?:_|$)/i

// NAME=value, export NAME=value, optional quotes, CRLF; only secret-looking names with a real value
export const parseEnv = (raw: string): { name: string; value: string }[] => {
  const out: { name: string; value: string }[] = []
  for (const line of raw.split(/\r?\n/)) {
    const m = line.match(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/)
    if (!m?.[1] || !ENV_SECRET_NAME.test(m[1])) continue
    let v = m[2] ?? ''
    const q = v.match(/^(["'])(.*)\1/)
    v = q ? q[2] ?? '' : v.replace(/\s+#.*$/, '')
    if (v.length >= 12 && !PLACEHOLDER.test(v)) out.push({ name: m[1], value: v })
  }
  return out
}

// vault line: SECRET_x='value' # rule source. A multi-line value (a PEM block) is written $'..\n..' so it
// stays on one line; the shell reads that form too
export const quote = (v: string) => /[\r\n]/.test(v)
  ? `$'${v.replace(/[\\']/g, '\\$&').replace(/\n/g, '\\n').replace(/\r/g, '\\r')}'`
  : `'${v.replace(/'/g, `'\\''`)}'`
const unescapeC = (v: string) => v.replace(/\\(.)/g, (_, c: string) => (c === 'n' ? '\n' : c === 'r' ? '\r' : c))
// "#forget SECRET_x" drops the entries above it; "#allow SECRET_x" keeps that value (the name is its
// hash) from ever being masked again. The file stays append-only either way
export const parseVault = (raw: string) => {
  let entries: { name: string; value: string; note: string }[] = []
  for (const line of raw.split('\n')) {
    const gone = line.match(/^#forget (SECRET_\w+)$/)?.[1]
    if (gone) { entries = entries.filter(e => e.name !== gone); continue }
    const [, name, q, c, note = ''] = line.match(/^(SECRET_\w+)=(?:('(?:[^']|'\\'')*')|\$'((?:[^'\\]|\\.)*)')(?: # (.*))?$/) ?? []
    if (name && q) entries.push({ name, value: q.slice(1, -1).replace(/'\\''/g, "'"), note })
    else if (name && c !== undefined) entries.push({ name, value: unescapeC(c), note })
  }
  return entries
}
// a later #forget clears an #allow too
export const allowedNames = (raw: string) => {
  const allowed = new Set<string>()
  for (const [, verb, name = ''] of raw.matchAll(/^#(allow|forget) (SECRET_\w+)$/gm)) {
    if (verb === 'allow') allowed.add(name)
    else allowed.delete(name)
  }
  return allowed
}

// git commit/push (or cz commit) as a command of its own: after ; & | newline ( or {, behind VAR=x, env,
// sudo, time, command, nohup or exec, as /path/to/git, with git's global options, inside bash/sh -c '...',
// and cz under uv/poetry/pipx run. Quoted text is blanked at the same length first, so `git commit` in a
// -m message never fires while offsets still point into the real command.
// ponytail: `sudo -u bob git`, `git --git-dir .. commit` (no =) and eval slip through; a shell parser if they matter
const GIT_SEND = /(?:^|[;&|\n({])\s*(?:[\w.-]+=\S*\s+|(?:sudo|time|command|env|nohup|exec)\s+(?:-\S+\s+)*)*(?:(?:\S*\/)?git((?:\s+-[Cc]\s+\S+|\s+--[\w-]+(?:=\S+)?)*)\s+(commit|push)|(?:(?:uv|poetry|pipx)\s+run\s+(?:--?\S+\s+)*)?cz\s+(commit|c))(?![\w-])/d
export const findGitSend = (command: string) => {
  const bodies = [...command.matchAll(/\b(?:ba|z)?sh\s+-c\s+(['"])((?:(?!\1)[^\\]|\\.)*)\1/g)].map(m => m[2] ?? '')
  const text = [command, ...bodies].join('\n')
  const blank = text.replace(/"(?:[^"\\]|\\.)*"|'[^']*'/g, q => q[0] + 'x'.repeat(q.length - 2) + q[0])
  const m = GIT_SEND.exec(blank)
  if (!m) return undefined
  const [s1, e1] = m.indices?.[1] ?? [0, 0]
  const c = /-C\s+(\S+)/d.exec(blank.slice(s1, e1))?.indices?.[1]
  const dir = c && text.slice(s1 + c[0], s1 + c[1])
  return { kind: m[2] === 'push' ? 'push' as const : 'commit' as const, cz: !!m[3], dir, args: text.slice(m.index + m[0].length) }
}

// what `git commit <args>` records: -a the work tree, explicit paths (--only/--include or bare) those
// paths, else the index. Quoted text (the -m message) is blanked first so no word in it reads as a flag.
// ponytail: a " inside a "$(cat <<EOF ...)" message breaks the blanking; a real shell parser if that bites
export const commitRange = (args: string): string[] => {
  const words = (args.replace(/"(?:[^"\\]|\\.)*"|'[^']*'/g, '""').split(/[;&|\n]/)[0] ?? '').trim().split(/\s+/).filter(Boolean)
  const paths: string[] = []
  let all = false
  for (let i = 0; i < words.length; i++) {
    const w = words[i] ?? ''
    if (w === '--') { paths.push(...words.slice(i + 1)); break }
    if (/^--(?:message|file|author|date|template|reuse-message|reedit-message|fixup|squash|cleanup|trailer)$/.test(w)) { i++; continue }
    if (w === '--all') all = true
    if (/^-[A-Za-z]/.test(w)) {
      if (/^-[A-Za-z]*a/.test(w)) all = true
      if (/^-[A-Za-z]*[mFCct]$/.test(w)) i++ // -m msg, -am msg: the next word is the argument
      continue
    }
    if (!w.startsWith('-')) paths.push(w)
  }
  // a quoted path was blanked: diff the whole work tree rather than a pathspec git would reject
  if (paths.some(p => p.includes('""'))) return ['HEAD']
  return all ? ['HEAD'] : paths.length ? ['HEAD', '--', ...paths] : ['--cached']
}

// node hooks/redact.ts  (typeof guard: the engine's module environment has no `process`)
if (typeof process !== 'undefined' && import.meta.url === `file://${process.argv[1]}`) {
  let n = 0
  const run = (t: string, mode?: Mode) => { n = 0; return redact(t, () => `SECRET_${++n}`, mode) }
  const hit = (t: string, value: string, why: string, mode?: Mode) => {
    const r = run(t, mode)
    if (!r.found.some(f => f.value === value) || r.text.includes(value)) throw new Error(`miss: ${why} -> ${r.text}`)
  }
  const pass = (t: string, why: string, mode?: Mode) => {
    const r = run(t, mode)
    if (r.found.length) throw new Error(`false positive: ${why} -> ${r.text}`)
  }

  const jwt = 'eyJ' + 'hbG' + 'ciO' + 'iJI' + 'UzI' + '1Ni' + 'J9.' + 'eyJ' + 'pc3' + 'MiO' + 'iJ0' + 'ZXN' + '0MT' + 'IzN' + 'DU2' + '.c2' + 'lnb' + 'mF0' + 'dXJ' + 'lMT' + 'IzN' + 'DU2'
  hit(`configure n8n token: ${jwt} thanks`, jwt, 'jwt')
  hit(`header ${jwt}`, jwt, 'jwt in tool output', 'high')
  hit('Xk9' + '#mP' + '2$v' + 'L7q' + 'Rt4' + 'wZn' + '8!Bc', 'Xk9' + '#mP' + '2$v' + 'L7q' + 'Rt4' + 'wZn' + '8!Bc', 'lon' + 'e p' + 'ass' + 'wor' + 'd')
  hit(`use cfat_${'a1B2'.repeat(11)} now`, `cfat_${'a1B2'.repeat(11)}`, 'cloudflare')
  hit('set' + ' CF' + '_AP' + 'I_T' + 'OKE' + 'N=X' + 'y7k' + 'Q2m' + 'N9p' + 'L4 ' + 'in ' + 'env', 'Xy7' + 'kQ2' + 'mN9' + 'pL4', 'PRE' + 'FIX' + '_TO' + 'KEN' + '=')
  hit('run' + ' ex' + 'por' + 't D' + 'B_P' + 'ASS' + 'WOR' + 'D=s' + '3cr' + '3t!' + 'PwQ' + 'z7 ' + 'fir' + 'st', 's3cr' + '3t!PwQz7', 'exp' + 'ort' + ' DB' + '_PA' + 'SSW' + 'ORD')
  hit('POS' + 'TGR' + 'ES_' + 'PAS' + 'SWO' + 'RD=' + 'Hun' + 'ter' + '2pwX' + 'k9Q', 'Hun' + 'ter' + '2pwX' + 'k9Q', '.en' + 'v l' + 'ine' + ' in' + ' to' + 'ol ' + 'out' + 'put', 'key' + 'word')
  hit('{"p' + 'ass' + 'wor' + 'd":' + ' "T' + 'r0u' + 'b4d' + 'or&' + '3Kq"}', 'Tr0' + 'ub4' + 'dor&3Kq', 'jso' + 'n q' + 'uoted')
  hit('has' + 'ło:' + ' Zx' + '9#k' + 'Lm2qW' + '7rT', 'Zx9#' + 'kLm2qW7rT', 'pol' + 'ish' + ' ke' + 'ywo' + 'rd')
  hit('db ' + 'at ' + 'pos' + 'tgr' + 'es:' + '//a' + 'pp:' + 'Hun' + 'ter' + '2pw' + '@db' + ':54' + '32/x', 'Hunt' + 'er2pw', 'url ' + 'creds')
  hit(`bot 123456789:AA${'b'.repeat(33)} ok`, `123456789:AA${'b'.repeat(33)}`, 'telegram')
  hit('lic' + 'enc' + 'e M' + 'NS1' + 'DPT' + '-01' + 'RMV' + 'V1-' + 'P85' + 'FTD' + '6-2' + '4CK' + 'NS2' + ' ok', 'MNS' + '1DP' + 'T-0' + '1RM' + 'VV1' + '-P8' + '5FT' + 'D6-' + '24C' + 'KNS' + '2', 'lic' + 'enc' + 'e key')
  const pem = '---' + '--B' + 'EGI' + 'N O' + 'PEN' + 'SSH' + ' PR' + 'IVA' + 'TE ' + 'KEY' + '---' + '--\n' + 'b3B' + 'lbn' + 'Nza' + 'C1r' + 'ZXk' + 'tdj' + 'EAAAA\n' + '---' + '--E' + 'ND ' + 'OPE' + 'NSS' + 'H P' + 'RIV' + 'ATE' + ' KE' + 'Y--' + '---'
  hit(`key:\n${pem}\ndone`, pem, 'private key')

  pass('dod' + 'ale' + 'm h' + 'asl' + 'o d' + 'o a' + 'nyt' + 'hin' + 'gll' + 'm, ' + 'ale' + ' mu' + 'sim' + 'y t' + 'o l' + 'epi' + 'ej ' + 'zab' + 'ezp' + 'iec' + 'zyc', 'pol' + 'ish' + ' pr' + 'ose')
  pass('has' + 'ło ' + 'zos' + 'tał' + 'o z' + 'mie' + 'nione', 'pol' + 'ish' + ' pr' + 'ose' + ' wi' + 'th ' + 'key' + 'wor' + 'd')
  pass('the' + ' to' + 'ken' + ' ex' + 'pir' + 'ed ' + 'yes' + 'ter' + 'day' + ', s' + 'ecr' + 'et ' + 'man' + 'age' + 'men' + 't i' + 's h' + 'ard', 'eng' + 'lis' + 'h p' + 'ros' + 'e')
  pass('che' + 'ck ' + 'htt' + 'ps:' + '//a' + 'pp.' + 'exa' + 'mpl' + 'e.c' + 'om/' + 'das' + 'hbo' + 'ard' + '/ma' + 'in', 'url')
  pass('/ho' + 'me/' + 'use' + 'r/p' + 'roj' + 'ect' + 's/a' + 'pp/' + 'doc' + 's/m' + 'anu' + 'al.' + 'pdf', 'path')
  pass('key' + ': s' + 'sh-' + 'rsa' + ' AA' + 'AAB' + '3Nz' + 'aC1' + 'yc2' + 'EAA' + 'AAD' + 'AQA' + 'BAA' + 'ACA' + 'QC9' + 'HXJ' + 's', 'pub' + 'lic' + ' key')
  pass('pas' + 'swo' + 'rd=' + '$DB' + '_PA' + 'SS ' + 'and' + ' to' + 'ken' + ': $' + '{AP' + 'I_T' + 'OKEN}', 'env' + ' pl' + 'ace' + 'hol' + 'ders')
  pass('pas' + 'swo' + 'rd:' + ' EN' + 'C[A' + 'ES2' + '56_' + 'GCM' + ',da' + 'ta:' + 'abc]', 'sop' + 's v' + 'alue')
  pass('Ref' + 'act' + 'or-' + 'Mod' + 'ule' + '-V2', 'lon' + 'e d' + 'ash' + 'ed ' + 'ide' + 'nti' + 'fier')
  pass('Qwe' + 'n3.' + '5-3' + '97B' + '-A17B', 'lon' + 'e m' + 'ode' + 'l n' + 'ame')
  pass('moo' + 'nsh' + 'ota' + 'i/k' + 'imi' + '-k3', 'lon' + 'e m' + 'ode' + 'l p' + 'ath')
  pass('use' + 'r@e' + 'xam' + 'ple' + '.com', 'lon' + 'e e' + 'mail')
  pass('tok' + 'en:' + ' $S' + 'ECR' + 'ET_3', 'alr' + 'ead' + 'y r' + 'eda' + 'cted')
  pass('$SE' + 'CRE' + 'T_a' + 'b12' + 'cd3' + '4ef', 'lon' + 'e p' + 'lac' + 'eho' + 'lder')
  for (const code of [
    'con' + 'st ' + 'tok' + 'en ' + '= g' + 'etT' + 'oke' + 'n(r' + 'eq)', 'api' + '_ke' + 'y=o' + 's.e' + 'nvi' + 'ron' + '["A' + 'PI_' + 'KEY"]', 'aut' + 'hor' + '=Jo' + 'hnS' + 'mith2',
    'tok' + 'en_' + 'url' + '=ht' + 'tps' + '://' + 'aut' + 'h.e' + 'xam' + 'ple' + '.co' + 'm/a' + 'ppl' + 'ica' + 'tio' + 'n/o' + '/to' + 'ken' + '/', 'pas' + 'swo' + 'rd ' + '= h' + 'ash' + 'lib' + '.sh' + 'a25' + '6(p' + 'w).' + 'hex' + 'dig' + 'est()',
    'tok' + 'eni' + 'zer' + '=se' + 'nte' + 'nce' + 'pie' + 'ce_' + 'v2', 'PAS' + 'SWO' + 'RD_' + 'FIL' + 'E=/' + 'run' + '/se' + 'cre' + 'ts/' + 'db_' + 'pw', 'sel' + 'f.a' + 'pi_' + 'key' + ' = ' + 'sel' + 'f.c' + 'onf' + 'ig.' + 'api' + '_key',
  ]) pass(code, `code: ${code}`, 'keyword')

  const known = new Map([['Zq8' + 'vR3' + 'nW7' + 'tK2' + 'pX9m', 'SECR' + 'ET_a1'], ['Zq8' + 'vR3' + 'nW7' + 'tK2' + 'pX9' + 'mXX', 'SECR' + 'ET_b2']])
  const s = scrubKnown('log' + ': Z' + 'q8v' + 'R3n' + 'W7t' + 'K2p' + 'X9m' + 'XX ' + 'and' + ' Zq' + '8vR' + '3nW' + '7tK' + '2pX' + '9m.', known)
  if (s !== 'log: $SECRET_b2 and $SECRET_a1.') throw new Error(`scrubKnown -> ${s}`)
  const byName = new Map([['SECR' + 'ET_a1', 'v1'], ['SECR' + 'ET_b2', 'v2']])
  const h = rehydrate('A=$' + 'SEC' + 'RET' + '_a1' + ' B=' + '${S' + 'ECR' + 'ET_' + 'b2}' + ' C=' + '$SE' + 'CRE' + 'T_z' + 'z D' + '=$S' + 'ECR' + 'ET_' + 'a1x', byName)
  if (h !== 'A=v1 B=v2 C=$SECRET_zz D=$SECRET_a1x') throw new Error(`rehydrate -> ${h}`)
  const raw = `SECRET_a1=${quote("it's")} # jwt prompt\nSECRET_2610041756_1='old'\njunk\n`
  const p = parseVault(raw)
  if (p.length !== 2 || p[0]?.value !== "it's" || p[0]?.note !== 'jwt' + ' pr' + 'ompt' || p[1]?.value !== 'old') throw new Error('par' + 'seV' + 'ault')
  const bare = 'SPO' + 'XH2' + 'ZYV' + 'A2K' + 'IFU' + 'F3B' + 'HXD' + 'Z'
  const env = parseEnv([
    'KESTRA_DEV_' + 'AUTH=' + bare, `export API_${'TOK'}EN="${bare}2"`, `DB_PASS${'WORD'}='${bare}3' # prod`, `CRLF_${'SEC'}RET=${bare}4\r`,
    'AWS_REGION=eu-central-1', 'AUTHOR=' + bare, 'TOKENIZER=' + bare, `${'API_'}KEY=$DB_PASS`, `SHORT_${'TOK'}EN=abc`, '# COMMENT_TOKEN=' + bare, 'NOEQUALS_' + 'TOKEN',
  ].join('\n'))
  const want = [bare, bare + '2', bare + '3', bare + '4']
  if (env.map(e => e.value).join() !== want.join()) throw new Error(`parseEnv -> ${env.map(e => `${e.name}=${e.value.length}`).join()}`)
  // a bare value, no label: only scrubKnown can catch it, which is the point of reading the file
  const bareOut = scrubKnown(`prefix: ${bare}`, new Map([[bare, 'SECR' + 'ET_x']]))
  if (bareOut !== 'prefix: $SECR' + 'ET_x') throw new Error(`bare -> ${bareOut}`)
  console.log('red' + 'act' + ': ok')
}
