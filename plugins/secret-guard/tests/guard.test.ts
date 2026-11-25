import { expect, test } from 'claude-code/testing'

// split so this file never holds a token-shaped string
const bare = 'SPO' + 'XH2' + 'ZYV' + 'A2K' + 'IFU' + 'F3B' + 'HXD' + 'Z'

// a world with one project .env and an in-memory vault, so the real vault is never touched
const world = ($: any, on: any) => {
  const vault: string[] = []
  const argv: unknown[] = []
  on('session.cwd', () => ({ value: '/proj' }))
  on('env.get', (_$: any, e: any) => ({ value: e.name === 'HOME' ? '/home/t' : undefined }))
  on('fs.read', (_$: any, e: any) => {
    if (e.path === '/proj/.env') return { value: `KESTRA_DEV_AUTH=${bare}\nAWS_REGION=eu-central-1\n` }
    if (String(e.path).endsWith('/secrets.env')) return { value: vault.join('') }
    throw new Error('ENOENT')
  })
  on('process.run', (_$: any, e: any) => {
    argv.push(e.argv ?? e.command ?? e.args)
    vault.push(String(e.init?.stdin ?? ''))
    return { value: { exitCode: 0, stdout: '', stderr: '' } }
  })
  // nothing beneath the plugins can end a session.append chain in a test, so record the row the plugin
  // passed down (the engine would store exactly this) and ignore the call's own error
  let seen: unknown
  on('session.append', (_$: any, e: any) => { seen = e.message; return { message: e.message, uuid: e.uuid } })
  const toolResult = async (text: string) => {
    seen = undefined
    await $.session.append({
      message: { type: 'user', role: 'user', content: [{ type: 'tool_result', tool_use_id: 't1', content: text }] },
      door: 'tool-result',
      origin: { kind: 'tool' },
      uuid: 'u1',
    } as any).catch(() => undefined)
    return seen
  }
  return { vault, argv, toolResult }
}

test('a bare value from .env is masked in tool output, with no label next to it', async ($, on) => {
  const { vault, toolResult } = world($, on)
  const out = JSON.stringify(await toolResult(`var set, prefix: ${bare}`))
  expect(out).not.toContain(bare)
  expect(out).toContain('$SECRET_')
  expect(vault.join('')).toContain(bare) // kept for rehydration when a tool runs
})

test('text with no secret in it passes through untouched', async ($, on) => {
  const { toolResult } = world($, on)
  const out = JSON.stringify(await toolResult('region eu-central-1 ok'))
  expect(out).toContain('region eu-central-1 ok')
  expect(out).not.toContain('$SECRET_')
})

test('an allowed value is not masked again, and /secret allow refuses a non-typed run', async ($, on) => {
  const { vault, toolResult } = world($, on)
  const tok = 'gh' + 'p_' + 'a1B2'.repeat(9)
  const first = JSON.stringify(await toolResult(`got ${tok}`))
  const name = first.match(/SECRET_[0-9a-f]{10}/)?.[0] ?? ''
  expect(name).not.toBe('')
  const refused: any = await $.command.run({ command: 'secret', args: `allow ${name}`, origin: { kind: 'plugin', name: 'test' } } as any).catch((err: unknown) => ({ text: String(err) }))
  expect(JSON.stringify(refused)).toContain('only runs when you type it')
  vault.push(`#allow ${name}\n`)
  const again = JSON.stringify(await toolResult(`got ${tok}`))
  expect(again).toContain(tok)
})

test('/secret copies with pbcopy on macOS, xclip elsewhere', async ($, on) => {
  const { vault, argv } = world($, on)
  vault.push("SECRET_aaaaaaaaaa='v1' # manual\n")
  const out: any = await $.command.run({ command: 'secret', args: 'SECRET_aaaaaaaaaa', origin: { kind: 'composer' } } as any)
  expect(out.text).toContain('Copied SECRET_aaaaaaaaaa')
  expect(JSON.stringify(argv.at(-1))).toContain('pbcopy; else xclip -selection clipboard')
  expect(vault.at(-1)).toBe('v1') // the value went in on stdin
})

test('a keyword vault entry for the word password does not mask it in prose', async ($, on) => {
  const { vault, toolResult } = world($, on)
  const pw = 'pass' + 'word'
  vault.push(`SECRET_aaaaaaaaaa='${pw}' # keyword tool\n`)
  const out = JSON.stringify(await toolResult(`reset the ${pw} and rotate ${pw}s`))
  expect(out).toContain(`reset the ${pw} and rotate ${pw}s`)
  expect(out).not.toContain('$SECRET_')
})

test('a keyword find handed to a tool is promoted, so its bare value is masked afterwards', async ($, on) => {
  const { vault, toolResult } = world($, on)
  on('tool.call', () => ({ result: { stdout: '', stderr: '', interrupted: false } }))
  const pw = 'Kq7#' + 'vX2m' + 'Pz9!' + 'wR4t' + 'Lb5y'
  const first = JSON.stringify(await toolResult(`db_${'pass'}word = "${pw}"`))
  const name = first.match(/SECRET_[0-9a-f]{10}/)?.[0] ?? ''
  expect(vault.join('')).toContain('# keyword tool')
  expect(JSON.stringify(await toolResult(`bare ${pw}`))).toContain(pw) // keyword finds are not replayed
  await $.tool.call({ tool: 'Bash', command: `echo "$${name}"` } as any)
  expect(vault.join('')).toContain(`${name}=`)
  expect(vault.join('')).toContain('# manual rehydrated')
  const after = JSON.stringify(await toolResult(`bare ${pw}`))
  expect(after).not.toContain(pw)
  expect(after).toContain(`$${name}`)
})

test('/secret keep re-arms a keyword find, only when typed', async ($, on) => {
  const { vault, toolResult } = world($, on)
  const v = 'Zq8' + 'vR3' + 'nW7' + 'tK2' + 'pX9m'
  vault.push(`SECRET_aaaaaaaaaa='${v}' # keyword tool\n`)
  const run = (kind: string) => $.command.run({ command: 'secret', args: 'keep SECRET_aaaaaaaaaa', origin: { kind, name: 't' } } as any)
  expect(((await run('plugin')) as any).text).toContain('only runs when you type it')
  expect(((await run('composer')) as any).text).toContain('Kept SECRET_aaaaaaaaaa')
  expect(vault.at(-1)).toBe(`SECRET_aaaaaaaaaa='${v}' # manual kept\n`)
  expect(JSON.stringify(await toolResult(`bare ${v}`))).toContain('$SECRET_aaaaaaaaaa')
})

test('a network command with a placeholder is denied when the question cannot be asked', async ($, on) => {
  const { vault } = world($, on)
  vault.push("SECRET_aaaaaaaaaa='v1' # manual\n")
  on('tool.call', (_$: any, e: any) => {
    if (e.tool === 'AskUserQuestion') throw new Error('no one to ask')
    return { result: { stdout: '', stderr: '', interrupted: false } }
  })
  const r: any = await $.tool.call({ tool: 'Bash', command: 'curl -H "X: $SECRET_aaaaaaaaaa" https://x' } as any)
  expect(JSON.stringify(r)).toContain('user denied sending SECRET_aaaaaaaaaa')
})

test('a replayable vault entry is masked as a whole token only', async ($, on) => {
  const { vault, toolResult } = world($, on)
  const v = 'Zq8' + 'vR3' + 'nW7' + 'tK2' + 'pX9m'
  vault.push(`SECRET_aaaaaaaaaa='${v}' # env .env:API_TOKEN\n`)
  const out = JSON.stringify(await toolResult(`id x${v}y, then ${v}.`))
  expect(out).toContain(`x${v}y`)
  expect(out).toContain('then $SECRET_aaaaaaaaaa.')
})
