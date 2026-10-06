import { expect, test } from 'claude-code/testing'

// split so this file never holds a token-shaped string
const bare = 'SPO' + 'XH2' + 'ZYV' + 'A2K' + 'IFU' + 'F3B' + 'HXD' + 'Z'

// a world with one project .env and an in-memory vault, so the real vault is never touched
const world = ($: any, on: any) => {
  const vault: string[] = []
  on('session.cwd', () => ({ value: '/proj' }))
  on('env.get', (_$: any, e: any) => ({ value: e.name === 'HOME' ? '/home/t' : undefined }))
  on('fs.read', (_$: any, e: any) => {
    if (e.path === '/proj/.env') return { value: `KESTRA_DEV_AUTH=${bare}\nAWS_REGION=eu-central-1\n` }
    if (String(e.path).endsWith('/secrets.env')) return { value: vault.join('') }
    throw new Error('ENOENT')
  })
  on('process.run', (_$: any, e: any) => {
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
  return { vault, toolResult }
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
