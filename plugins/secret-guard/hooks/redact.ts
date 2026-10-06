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
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
// getToken(req), os.environ[, self.token, https://..., /run/secrets/x
const CODE = /[()[\]{}<>]|:\/\/|^[/~.$%@]|^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+$/

// keyword value: not a placeholder, code or plain word (incl. Polish letters), and looks random
const plausible = (v: string) =>
  !PLACEHOLDER.test(v) && !CODE.test(v) && !/^[\p{L}_.-]+$/u.test(v) && !UUID.test(v) &&
  (entropy(v) >= 3 || classes(v) >= 3)

// high: a known format, safe on any text. keyword: a label + value, only where false positives are cheap
export type Mode = 'high' | 'keyword' | 'all'
type Rule = { re: RegExp; tier: 'high' | 'keyword'; check?: (v: string) => boolean }

// value is the first capture group when present, else the whole match
const RULES: readonly Rule[] = [
  { tier: 'high', re: /-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----[\s\S]*?(?:KEY(?: BLOCK)?-----|$)/g },
  { tier: 'high', re: /\beyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]{8,}/g }, // JWT: HA, n8n, homelable, OVH
  { tier: 'high', re: /\bcf(?:k|ut|at)_[A-Za-z0-9]{40,}/g }, // Cloudflare
  { tier: 'high', re: /\bglsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}\b/g }, // Grafana service account
  { tier: 'high', re: /\b\d{5,16}:A[\w-]{34}\b/g }, // Telegram bot
  { tier: 'high', re: /\b(?:AKIA|ASIA)[A-Z2-7]{16}\b/g }, // AWS key id
  { tier: 'high', re: /\bAGE-SECRET-KEY-1[A-Z0-9]{58}\b/g }, // age identity (sops)
  { tier: 'high', re: /\b(?:sk-ant-|sk-|ghp_|gho_|github_pat_|glpat-|xox[bpa]-)[\w-]{20,}/g },
  { tier: 'high', re: /\b[a-z][a-z0-9+.-]{1,20}:\/\/[^\s:@/]{1,64}:([^\s@/]{3,128})@/gi, check: v => !PLACEHOLDER.test(v) }, // scheme://user:pass@
  { tier: 'high', re: /\b(?:Bearer|Basic)\s+([\w.~+/=-]{16,})/gi, check: v => !PLACEHOLDER.test(v) },
  { tier: 'high', re: /\b[A-Z0-9]{5,8}(?:-[A-Z0-9]{5,8}){3,}\b/g, check: v => /\d/.test(v) && /[A-Z]/.test(v) && !UUID.test(v) }, // licence keys
  {
    // keyword must stand alone or between separators: CF_API_TOKEN yes, author / tokenizer / bypass no
    tier: 'keyword',
    re: /(?<![\p{L}\d])(?:[\w.-]{0,30}?[_.-])?(?:passw(?:or)?d|passwd|pwd|pass(?:phrase)?|has[lł][oa]|secret|token|api[_-]?key|auth[_-]?(?:token|key)|credentials?|creds|master[_-]?key|private[_-]?key)(?:[_.-][\w.-]{0,20})?(?![\p{L}\d])["']?\s*(?::=|=>|[:=])\s*["'`]?([^\s"'`,;]{6,200})/giu,
    check: plausible,
  },
]

// whole prompt is one opaque string, e.g. a pasted password or API token
const LONE = /^\s*(\S{12,})\s*$/
const isOpaque = (s: string) =>
  UUID.test(s) ||
  !/^(https?:|\/|~|\.|@|\$)/.test(s) && !/\.\w{1,5}$/.test(s) && !/@[\w-]+\./.test(s) && !PLACEHOLDER.test(s) &&
  !/^[A-Za-z0-9]+(?:[-_./:][A-Za-z0-9]+)+$/.test(s) && // Qwen3.5-397B-A17B, moonshotai/kimi-k3, GENERIC_OPEN_AI
  (classes(s) >= 3 || (s.length >= 20 && entropy(s) >= 3.5))

export type Found = { name: string; value: string; rule: string }

// nameFor maps a value to its vault name (existing or new)
export const redact = (
  text: string,
  nameFor: (value: string) => string,
  mode: Mode = 'all',
): { text: string; found: Found[] } => {
  const found: Found[] = []
  const stash = (value: string, rule: string) => {
    const name = nameFor(value)
    if (!found.some(f => f.name === name)) found.push({ name, value, rule })
    return `$${name}`
  }

  const lone = mode === 'all' ? text.match(LONE)?.[1] : undefined
  if (lone && isOpaque(lone)) {
    return { text: text.replace(lone, stash(lone, 'lone')), found }
  }

  let out = text
  for (const [i, { re, tier, check }] of RULES.entries()) {
    if (mode === 'high' && tier !== 'high') continue
    out = out.replace(re, (whole: string, ...groups: unknown[]) => {
      const value = typeof groups[0] === 'string' && groups[0] !== '' ? groups[0] : whole
      if (value.startsWith('$SECRET_') || (check && !check(value))) return whole
      const at = whole.lastIndexOf(value) // value ends the match; lastIndexOf so a key containing it is left alone
      return whole.slice(0, at) + stash(value, tier === 'high' ? `rule${i}` : 'keyword') + whole.slice(at + value.length)
    })
  }
  return { text: out, found }
}

// known vault values anywhere in text, longest first so one value inside another can't split it
export const scrubKnown = (text: string, known: ReadonlyMap<string, string>): string => {
  let out = text
  for (const [value, name] of [...known].sort((a, b) => b[0].length - a[0].length)) {
    if (value.length >= 8 && out.includes(value)) out = out.split(value).join(`$${name}`)
  }
  return out
}

// $SECRET_x / ${SECRET_x} back to values; unknown names left as typed
export const rehydrate = (text: string, byName: ReadonlyMap<string, string>): string =>
  text.replace(/\$\{?(SECRET_\w+?)\}?(?![\w])/g, (whole, name: string) => byName.get(name) ?? whole)

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

// vault line: SECRET_x='value' # rule source
export const quote = (v: string) => `'${v.replace(/'/g, `'\\''`)}'`
export const parseVault = (raw: string) => {
  const entries: { name: string; value: string; note: string }[] = []
  for (const line of raw.split('\n')) {
    const [, name, q, note = ''] = line.match(/^(SECRET_\w+)=('(?:[^']|'\\'')*')(?: # (.*))?$/) ?? []
    if (name && q) entries.push({ name, value: q.slice(1, -1).replace(/'\\''/g, "'"), note })
  }
  return entries
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
  hit('723' + '7b1' + '7b3' + 'b03' + '91d' + '264' + '647' + 'af1' + '532' + 'd13' + '570' + 'ef9' + '3a16', '723' + '7b1' + '7b3' + 'b03' + '91d' + '264' + '647' + 'af1' + '532' + 'd13' + '570' + 'ef9' + '3a16', 'lon' + 'e h' + 'ex ' + 'api' + ' to' + 'ken')
  hit('763' + '849' + '42-' + 'ec0' + '3-4' + '457' + '-b7' + '4a-' + 'bcb' + '477' + 'e19' + '714', '763' + '849' + '42-' + 'ec0' + '3-4' + '457' + '-b7' + '4a-' + 'bcb' + '477' + 'e19' + '714', 'lon' + 'e u' + 'uid' + ' (p' + 'rox' + 'mox' + ' to' + 'ken' + ' se' + 'cre' + 't)')
  hit('Aut' + 'hor' + 'iza' + 'tio' + 'n\n ' + ' be' + 'are' + 'r a' + 'bcd' + 'efg' + 'hij' + 'klm' + 'nop' + '123' + '4', 'abc' + 'def' + 'ghi' + 'jkl' + 'mno' + 'p12' + '34', 'low' + 'erc' + 'ase' + ' be' + 'arer')
  hit(`use cfat_${'a1B2'.repeat(11)} now`, `cfat_${'a1B2'.repeat(11)}`, 'cloudflare')
  hit('set' + ' CF' + '_AP' + 'I_T' + 'OKE' + 'N=X' + 'y7k' + 'Q2m' + 'N9p' + 'L4 ' + 'in ' + 'env', 'Xy7' + 'kQ2' + 'mN9' + 'pL4', 'PRE' + 'FIX' + '_TO' + 'KEN' + '=')
  hit('run' + ' ex' + 'por' + 't D' + 'B_P' + 'ASS' + 'WOR' + 'D=s' + '3cr' + '3t!' + 'Pw ' + 'fir' + 'st', 's3cr' + '3t!Pw', 'exp' + 'ort' + ' DB' + '_PA' + 'SSW' + 'ORD')
  hit('POS' + 'TGR' + 'ES_' + 'PAS' + 'SWO' + 'RD=' + 'Hun' + 'ter' + '2pwX', 'Hun' + 'ter' + '2pwX', '.en' + 'v l' + 'ine' + ' in' + ' to' + 'ol ' + 'out' + 'put', 'key' + 'word')
  hit('{"p' + 'ass' + 'wor' + 'd":' + ' "T' + 'r0u' + 'b4d' + 'or&' + '3"}', 'Tr0' + 'ub4' + 'dor&3', 'jso' + 'n q' + 'uoted')
  hit('has' + 'ło:' + ' Zx' + '9#k' + 'Lm2q', 'Zx9#' + 'kLm2q', 'pol' + 'ish' + ' ke' + 'ywo' + 'rd')
  hit('db ' + 'at ' + 'pos' + 'tgr' + 'es:' + '//a' + 'pp:' + 'Hun' + 'ter' + '2pw' + '@db' + ':54' + '32/x', 'Hunt' + 'er2pw', 'url ' + 'creds')
  hit(`bot 123456789:A${'b'.repeat(34)} ok`, `123456789:A${'b'.repeat(34)}`, 'telegram')
  hit('lic' + 'enc' + 'e M' + 'NS1' + 'DPT' + '-01' + 'RMV' + 'V1-' + 'P85' + 'FTD' + '6-2' + '4CK' + 'NS2' + ' ok', 'MNS' + '1DP' + 'T-0' + '1RM' + 'VV1' + '-P8' + '5FT' + 'D6-' + '24C' + 'KNS' + '2', 'lic' + 'enc' + 'e key')
  const pem = '---' + '--B' + 'EGI' + 'N O' + 'PEN' + 'SSH' + ' PR' + 'IVA' + 'TE ' + 'KEY' + '---' + '--\n' + 'b3B' + 'lbn' + 'Nza' + 'C1r' + 'ZXk' + 'tdj' + 'EAAAA'
  hit(`key:\n${pem}`, pem, 'truncated private key')

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
