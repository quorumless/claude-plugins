import { expect, test } from 'claude-code/testing'

import { allowedNames, type Mode, parseVault, quote, redact, rehydrate, replayable, scrubKnown } from '../hooks/redact.ts'

// regression corpus from the vault audit. Secret-looking strings are split so this file never holds one.
const j = (...p: string[]) => p.join('')
const run = (t: string, mode: Mode) => { let n = 0; return redact(t, () => `SECRET_${++n}`, mode) }
// value must be found and gone from the text
const masked = (t: string, value: string, mode: Mode = 'keyword') => {
  const r = run(t, mode)
  expect(r.found.map(f => f.value)).toContain(value)
  expect(r.text).not.toContain(value)
}
// nothing found, text unchanged
const clean = (t: string, mode: Mode = 'all') => {
  const r = run(t, mode)
  expect(r.found).toEqual([])
  expect(r.text).toBe(t)
}

test('fix 1: keyword and lone vault entries are not replayed', () => {
  expect(replayable(j('pass', 'word'), 'keyword tool')).toBe(false)
  expect(replayable(j('Xk9#', 'mP2$vL7q'), 'lone prompt')).toBe(false)
  expect(replayable('anything-at-all', 'env .env:API_TOKEN')).toBe(true)
  expect(replayable('anything-at-all', 'manual')).toBe(true)
  expect(replayable('anything-at-all', '')).toBe(false)
})

test('fix 1: high-tier entries replay only while today\'s rule still matches', () => {
  const ghp = j('gh', 'p_', 'a1B2'.repeat(9))
  expect(replayable(ghp, 'prefix prompt')).toBe(true)
  expect(replayable(ghp, 'rule7 tool')).toBe(true) // legacy note
})

test('fix 1: replay matches whole tokens only', () => {
  const pw = j('pass', 'word')
  const known = new Map([[pw, 'SECRET_aa']])
  expect(scrubKnown(j('the ', pw, 's are ', pw, '_x and my', pw), known)).toBe(j('the ', pw, 's are ', pw, '_x and my', pw))
  expect(scrubKnown(j('it is ', pw, '.'), known)).toBe('it is $SECRET_aa.')
  // a value that starts or ends in a non-word char needs no boundary on that side
  const odd = j('!Zq8', 'vR3nW', '7tK2/')
  expect(scrubKnown(j('ab', odd, 'cd'), new Map([[odd, 'SECRET_bb']]))).toBe('ab$SECRET_bbcd')
})

test('fix 2: a placeholder is never taken as the keyword', () => {
  clean('$SECRET_ab12cd34ef: module_version: 0.2.0', 'keyword')
  clean('${SECRET_ab12cd34ef}: module_version: 0.2.0', 'keyword')
  clean('prefix $SECRET_ab12cd34ef=module_version_0.2.0', 'keyword')
})

test('fix 3: Bearer/Basic is case-sensitive, same line, token charset', () => {
  clean('ls examples/basic\n.spacelift/config.yml')
  clean('modules:\n  examples/basic\n  .spacelift/config.yml', 'keyword')
  clean('curl -H "Authorization: Bearer YOUR_TOKEN_HERE"', 'keyword')
  clean('Authorization:\n bearer abcdefghijklmnop1234', 'keyword')
  const tok = j('h7Fq', '2LmX', '9pRt', 'Kw3Z', 'b8Vn', 'C4yD')
  masked(`curl -H "Authorization: Bearer ${tok}"`, tok)
  expect(replayable('.spacelift/config.yml', 'rule9 tool')).toBe(false)
})

test('fix 4: keyword tier rejects audit false positives', () => {
  clean('docs/x_credential.md:12: foo: bar-baz-1', 'keyword')
  clean('x_credential.md:123456: foo: bar-baz-1', 'keyword')
  clean(j('master_user_', 'secret_arn = "arn:aws:secretsmanager:us-east-1:000000000000:secret:x"'), 'keyword')
  clean(j('api_', 'key_id = "01ARZ3NDEKTSV4RRFFQ69G5FAV"'), 'keyword')
  clean(j('checksum/', 'secret: ', 'a3f1'.repeat(16)), 'keyword')
  clean(j('pass', 'word = var.db_', 'password'), 'keyword')
  clean(j('pass', ': Hx8kQ2mZ9vL4pR'), 'keyword') // bare pass dropped
  clean(j('db_', 'password = "your_', 'password_here"'), 'keyword')
  clean(j('api_', 'token: <', 'token>'), 'keyword')
  // key boundary alone decides these: the value is random enough, only what precedes the key differs
  const rnd = j('Hx8k', 'Q2mZ', '9vL4', 'pRb7')
  clean(j('config/app_', 'secret: ', rnd), 'keyword')
  clean(j('notes.md:3:api_', 'token=', rnd), 'keyword')
  masked(j('config app_', 'secret: ', rnd), rnd)
  masked(j('notes.md:3: api_', 'token=', rnd), rnd)
  clean(j('client_', 'secret:\n  Hx8kQ2mZ9vL4pR'), 'keyword') // separator and value on different lines
  clean(j('token_', 'path: secrets/prod/app.json'), 'keyword')
  clean(j('secret', 'Name: app-prod-db'), 'all')
  clean(j('token: ', 'bar-baz-1'), 'keyword') // too short and too regular
})

test('fix 4: keyword tier still masks random labelled values', () => {
  const pw = j('Kq7#', 'vX2m', 'Pz9!', 'wR4t', 'Lb5y')
  masked(j('db_', 'password = "', pw, '"'), pw)
  masked(j('{"client_', 'secret": "', pw, '"}'), pw)
  masked(j('connect(api_', 'key=', pw, ', retries)'), pw)
})

// synthetic AWS-shaped values
const keyId = j('AS', 'IA', 'Q3EG', 'B7XK', 'M2PL', 'W4ZN')
const secretKey = j('h7Fq2', 'LmX9p', 'RtKw3', 'Zb8Vn', 'C4yDa', '1sE6u', 'J0oGi', 'T5rQ/')
const stsToken = j('IQoJ', 'b3Jp', 'Z2lu', 'X2Vj', 'EH0a') + 'Kq7vX2mPz9wR4tLb'.repeat(7)

test('fix 5: AWS credentials from aws sts JSON, CloudTrail and tab-separated output are masked', () => {
  const json = `{"Credentials": {"AccessKeyId": "${keyId}", "SecretAccessKey": "${secretKey}", "SessionToken": "${stsToken}"}}`
  for (const v of [keyId, secretKey, stsToken]) masked(json, v)
  masked(`"sessionToken": "${'Fz9/'.repeat(30)}"`, 'Fz9/'.repeat(30))
  const tsv = `ASSUME FAILED ${keyId}\t${secretKey}\t${stsToken}`
  for (const v of [keyId, secretKey, stsToken]) masked(tsv, v)
  masked(j('aws_secret_', 'access_key = ', secretKey), secretKey)
  masked(`token ${stsToken} end`, stsToken, 'high')
})

test('fix 5: AWS documentation examples are not masked', () => {
  clean(j('aws_access_key_id = AKIA', 'IOSFODNN7', 'EXAMPLE'), 'keyword')
  clean(j('aws_secret_', 'access_key = wJalrXUtnFEMI/K7MDENG/', 'bPxRfiCY', 'EXAMPLEKEY'), 'keyword')
  clean(j('AKIA', 'IOSFODNN7', 'EXAMPLE', '\twJalrXUtnFEMI/K7MDENG/', 'bPxRfiCY', 'EXAMPLEKEY'), 'keyword')
  // lowercase hex beside a key id is no secret: only the id is masked
  expect(run(`${keyId} commit ${'a3f19c'.repeat(6)}abcd`, 'high').found.map(f => f.rule)).toEqual(['aws-key-id'])
})

test('fix 6: a routable GitLab PAT is masked with its full tail', () => {
  const pat = j('gl', 'pat-', 'Kq7vX2mPz9wR4tLb', 'h7Fq2LmX9pRt', '.01', 'x3k9a2b')
  const r = run(`token ${pat} end`, 'high')
  expect(r.found.map(f => f.value)).toEqual([pat])
  expect(r.text).toBe('token $SECRET_1 end')
})

test('prefix rule: a dashed resource name after sk- is not a key', () => {
  clean(j('s', 'k-backup-replication-eu-central-1'), 'keyword')
  const ghp = j('gh', 'p_', 'a1B2'.repeat(9))
  masked(`push with ${ghp}`, ghp, 'high')
})

test('fix 7: a PEM block needs its END line', () => {
  const begin = j('-----BEGIN ', 'RSA PRIVATE', ' KEY-----')
  const end = j('-----END ', 'RSA PRIVATE', ' KEY-----')
  clean(`the file starts with ${begin} and then base64.\nNext paragraph about module_version and more prose.`, 'high')
  const block = `${begin}\n${'MIIEowIBAAKCAQEA7vX2mPz9wR4t'.repeat(3)}\n${end}`
  const r = run(`key:\n${block}\nafter the key`, 'high')
  expect(r.found.map(f => f.value)).toEqual([block])
  expect(r.text).toBe('key:\n$SECRET_1\nafter the key')
})

test('fix 8: Telegram needs the real bot token shape', () => {
  clean('arn:aws:sts::123456789012:assumed-role x 123456789012:AWSReservedSSO_AdministratorAccess_0123456789abcdef/x', 'high')
  clean('role 123456789012:AWSReservedSSO_PowerUser_01234567ab/x', 'high') // matched the old rule
  const bot = j('123456789', ':AA', 'Hx8kQ2mZ9vL4pRb7Fq2LmX9pRtKw3Zb8V')
  masked(`bot ${bot} ok`, bot, 'high')
})

test('fix 9: TLS cipher-suite names are not licence keys', () => {
  clean('ssl_ciphers ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384', 'high')
  clean('ECDHE-ECDSA-CHACHA20-POLY1305', 'all')
  const lic = j('MNS1D', 'PT-01R', 'MVV1-P85', 'FTD6-24C', 'KNS2')
  masked(`licence ${lic} ok`, lic, 'high')
})

test('fix 10: a pasted SHA, UUID, ULID, ARN or digest is not a lone secret', () => {
  for (const s of [
    j('3f9c2a1', 'b7e4d6f0', '8a5c3e1d', '9b7f2a4c', '6e8d0b13'), 'a3f19c2', j('7637', '8942-ec03-4457-b74a-', 'bcb477e19714'),
    '01ARZ3NDEKTSV4RRFFQ69G5FAV', 'arn:aws:iam::000000000000:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_Admin',
    `sha256:${'a3f1'.repeat(16)}`, `registry.example.com/app@sha256:${'a3f1'.repeat(16)}`,
  ]) clean(s, 'all')
  const pw = j('Xk9#', 'mP2$', 'vL7q', 'Rt4w', 'Zn8!Bc')
  masked(pw, pw, 'all')
})

test('fix 12: #forget drops earlier entries, #allow is read as a name set', () => {
  const raw = "SECRET_aaaaaaaaaa='v1' # env .env:A\nSECRET_bbbbbbbbbb='v2' # prefix tool\n#forget SECRET_aaaaaaaaaa\n#allow SECRET_bbbbbbbbbb\n"
  expect(parseVault(raw).map(e => e.name)).toEqual(['SECRET_bbbbbbbbbb'])
  expect([...allowedNames(raw)]).toEqual(['SECRET_bbbbbbbbbb'])
  expect([...allowedNames(raw + '#forget SECRET_bbbbbbbbbb\n')]).toEqual([])
  expect([...allowedNames(raw + '#forget SECRET_bbbbbbbbbb\n#allow SECRET_bbbbbbbbbb\n')]).toEqual(['SECRET_bbbbbbbbbb'])
  // seen again after the forget: live again
  expect(parseVault(raw + "SECRET_aaaaaaaaaa='v1' # env .env:A\n").map(e => e.name)).toEqual(['SECRET_bbbbbbbbbb', 'SECRET_aaaaaaaaaa'])
})

test('fix 13: multi-line vault values round-trip, old entries still parse', () => {
  const pem = j('-----BEGIN ', 'RSA PRIVATE', ' KEY-----\nMIIEow\\x\'q\r\n', '-----END ', 'RSA PRIVATE', ' KEY-----')
  const raw = `SECRET_aaaaaaaaaa=${quote(pem)} # pem tool\nSECRET_bbbbbbbbbb=${quote("it's")} # env .env:A\nSECRET_2610041756_1='old'\n`
  expect(raw.split('\n').length).toBe(4)
  const p = parseVault(raw)
  expect(p.map(e => e.value)).toEqual([pem, "it's", 'old'])
  expect(p[0]?.note).toBe('pem tool')
})

test('true positives: ghp_ token and JWT anywhere', () => {
  const ghp = j('gh', 'p_', 'Zq8v', 'R3nW', '7tK2', 'pX9m', 'Hx8k', 'Q2mZ', '9vL4', 'pRb7', 'Fq2L')
  masked(`remote: https://x.example/${ghp} ok`, ghp, 'high')
  const jwt = j('eyJ', 'hbGciOiJIUzI1NiJ9', '.eyJ', 'pc3MiOiJ0ZXN0MTIzNDU2', '.c2lnbmF0dXJl', 'MTIzNDU2')
  masked(`Authorization: ${jwt}`, jwt, 'high')
})

test('review 5: no rule goes quadratic on a 1 MB single line', () => {
  const id = j('AS', 'IA', 'Q3EG', 'B7XK', 'M2PL', 'W4ZN')
  const begin = j('-----BEGIN ', 'RSA PRIVATE', ' KEY-----')
  for (const t of [(id + ' ').repeat(50000), (begin + ' ').repeat(40000), begin + 'x'.repeat(1 << 20), 'a b '.repeat(260000)]) {
    const t0 = performance.now()
    run(t, 'all')
    expect(performance.now() - t0).toBeLessThan(500)
  }
})

test('review 9: ${SECRET_x} followed by a word char rehydrates whole', () => {
  const byName = new Map([['SECRET_a1', 'v1']])
  expect(rehydrate('${SECRET_a1}y $SECRET_a1 $SECRET_a1x ${SECRET_zz}', byName)).toBe('v1y v1 $SECRET_a1x ${SECRET_zz}')
})
