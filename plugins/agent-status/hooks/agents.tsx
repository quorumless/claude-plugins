import type { AgentInfo, AgentStatus, EngineInterface, Register } from 'claude-code'

const PANE = 'agents'
const LIVE: AgentStatus[] = ['pending', 'running', 'waiting', 'idle']

const DOT: Record<AgentStatus, [string, string?]> = {
  pending: ['◌'],
  running: ['●', 'green'],
  waiting: ['◐', 'yellow'],
  idle: ['○'],
  completed: ['✓'],
  failed: ['✗', 'red'],
  killed: ['✗'],
}

// ponytail: per-module memory, a reload forgets start times (they restart at first sight)
type Seen = { start: number; respondedAt?: number; tool?: string; calls: number }
const seen = new Map<string, Seen>()

const touch = (id: string, now: number) => {
  let one = seen.get(id)
  if (!one) seen.set(id, (one = { start: now, calls: 0 }))
  return one
}

// 42s, 4m12, 1h05
export const dur = (ms: number) => {
  const s = Math.max(0, Math.floor(ms / 1000))
  if (s < 60) return `${s}s`
  if (s < 3600) return `${Math.floor(s / 60)}m${String(s % 60).padStart(2, '0')}`
  return `${Math.floor(s / 3600)}h${String(Math.floor(s / 60) % 60).padStart(2, '0')}`
}

// silence only matters while it should be talking
export const staleColor = (ms: number, status: AgentStatus) =>
  status !== 'running' ? undefined : ms < 30_000 ? undefined : ms < 120_000 ? 'yellow' : 'red'

// general-purpose -> general, mcp__claude_ai_Gmail__get_thread -> get_thread
const shortType = (t: string) => t.replace(/-purpose$/, '').replace(/^.*:/, '')
const shortTool = (t: string) => t.replace(/^mcp__.*__/, '')

const cell = (s: string, n: number) => (s.length > n ? s.slice(0, n - 1) + '…' : s.padEnd(n))

// the 1s redraw tick only runs while something is live
let active = false

async function rows($: EngineInterface, liveOnly: boolean) {
  const now = await $.clock.now()
  const list = (await $.agent.list()).filter(a => !liveOnly || LIVE.includes(a.status))
  active = list.some(a => LIVE.includes(a.status))
  return list.map(a => ({ a, s: touch(a.id, now), now }))
}

export const register: Register = on => {
  const row = (Text: any, { a, s, now }: { a: AgentInfo; s: Seen; now: number }, width: number, wide: boolean) => {
    const ago = s.respondedAt === undefined ? undefined : now - s.respondedAt
    const [dot, dotColor] = DOT[a.status]
    const ended = !LIVE.includes(a.status)
    const fixed = wide ? 2 + 9 + 6 + 6 + 11 + 4 : 2 + 9 + 6 + 6 + 11

    return (
      <Text key={a.id} wrap="truncate" dimColor={ended}>
        <Text color={dotColor}>{dot} </Text>
        {cell(shortType(a.type), 8)} {cell(dur(now - s.start), 5)}{' '}
        <Text color={staleColor(ago ?? now - s.start, a.status)}>{cell(ago === undefined ? '—' : `↻${dur(ago)}`, 5)}</Text>{' '}
        {cell(s.tool ? shortTool(s.tool) : '—', 10)}{' '}
        {wide ? `${String(s.calls).padStart(3)} ` : ''}
        <Text dimColor>{cell(a.name ?? a.description, Math.max(4, width - fixed))}</Text>
      </Text>
    )
  }

  on('session.start', async ($, e, next) => {
    await $.command.register({ name: 'agents', description: 'Show background agents in a pane' })
    $.clock.every(1000, () => {
      if (active) $.ui.invalidate('ui.render')
    })

    return next(e)
  })

  on('command.run', { command: 'agents' }, async $ => {
    await $.ui.open({ id: PANE, title: 'Agents' })

    return { text: 'Agents pane opened.' }
  })

  on('agent.spawn', async ($, e, next) => {
    const r = await next(e)
    if (r.agentId) {
      touch(r.agentId, await $.clock.now())
      active = true
    }

    return r
  })

  on('turn.step', async function* ($, e, next) {
    const r = yield* next(e)
    if (e.agentId) touch(e.agentId, await $.clock.now()).respondedAt = await $.clock.now()

    return r
  })

  on('tool.call', async ($, e, next) => {
    if (e.agentId) {
      const s = touch(e.agentId, await $.clock.now())
      s.tool = e.tool
      s.calls += 1
    }

    return next(e)
  })

  // composes with whatever else draws the band (cc-status): our rows on top
  on('ui.render', { component: 'AbovePrompt' }, async ($, e, next) => {
    const below = await next(e)
    if (e.props.hasSurvey) return below

    const list = await rows($, true)
    if (list.length === 0) return below

    const { Box, Text } = $.ui.resolve(e)

    return (
      <Box flexDirection="column">
        {list.map(r => row(Text, r, e.props.bodyColumns, false))}
        {below}
      </Box>
    )
  })

  on('ui.render', { component: 'Pane', requestId: PANE }, async ($, e) => {
    const list = await rows($, false)
    const { Box, Text } = $.ui.resolve(e)
    const width = e.props.bodyColumns

    return (
      <Box flexDirection="column">
        <Text dimColor wrap="truncate">
          {'  '}
          {cell('type', 8)} {cell('run', 5)} {cell('reply', 5)} {cell('call', 10)} {'  #'} task
        </Text>
        {list.length === 0 ? <Text dimColor>No agents this session.</Text> : list.map(r => row(Text, r, width, true))}
      </Box>
    )
  })
}
