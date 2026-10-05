import { expect, mock, test } from 'claude-code/testing'

import { dur, staleColor } from '../hooks/agents'

test('durations and staleness', () => {
  expect(dur(42_000)).toBe('42s')
  expect(dur(252_000)).toBe('4m12')
  expect(dur(3_900_000)).toBe('1h05')
  expect(staleColor(10_000, 'running')).toBe(undefined)
  expect(staleColor(45_000, 'running')).toBe('yellow')
  expect(staleColor(200_000, 'running')).toBe('red')
  expect(staleColor(200_000, 'idle')).toBe(undefined)
})

test('band lists live agents above what is beneath', async ($, on) => {
  const clock = mock.clock(on)
  on('agent.list', () => ({ value: [
    { id: 'a1', description: 'find auth flow', type: 'Explore', status: 'running' },
    { id: 'a2', description: 'old one', type: 'general-purpose', status: 'completed' },
  ] }) as any)
  on('tool.call', () => ({ result: 'ok' }) as any)
  on('ui.render', { component: 'AbovePrompt' }, ($, e) => {
    const { Text } = $.ui.resolve(e)
    return <Text key="below">cc-status</Text>
  })

  await $.tool.call({ tool: 'Grep', input: { pattern: 'x' }, agentId: 'a1' } as any)
  await clock.advance(45_000)

  for (const surface of ['terminal', 'desktop'] as const) {
    const ui = await $.ui.mount({
      plugin: 'agent-status',
      surface,
      component: 'AbovePrompt',
      props: { hasSurvey: false, isWorking: true, maxRows: 10, bodyColumns: 80 } as any,
    })
    const texts = (await ui.findAll({ type: 'Text' })).map(t => t.text).join('\n')
    expect(texts).toContain('Explore')
    expect(texts).toContain('Grep')
    expect(texts).toContain('find auth flow')
    expect(texts).not.toContain('old one')
    expect(texts).toContain('cc-status')
  }
})
