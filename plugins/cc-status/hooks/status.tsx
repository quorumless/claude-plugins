import type { Register } from 'claude-code'

// empty to full, quarter steps
const CIRCLES = ['○', '◔', '◑', '◕', '●']

const color = (pct: number) => (pct < 50 ? 'green' : pct < 75 ? 'yellow' : 'red')

const size = (tokens: number) =>
  tokens >= 1e6 ? `${tokens / 1e6}M` : `${Math.round(tokens / 1e3)}k`

// claude-sonnet-5-5 -> sonnet 5.5, claude-haiku-4-5-20251001 -> haiku 4.5
const short = (id: string) =>
  id.replace(/^claude-/, '').replace(/-\d{8}$/, '').replace(/\[.*\]$/, '').replace(/-(\d+)-(\d+)$/, ' $1.$2').replace(/-(\d+)$/, ' $1')

// written by the secret-guard mod; absent means it isn't loaded
const GUARD = { plugin: 'secret-guard', key: 'health' } as const

export const register: Register = on => {
  on('turn.complete', ($, e, next) => {
    $.ui.invalidate('ui.render')

    return next(e)
  })

  on('ui.render', { component: 'AbovePrompt' }, async ($, e, next) => {
    const { context } = await $.session.usage()
    const model = await $.session.model()
    if (e.props.hasSurvey || context.percent === undefined) {
      return next(e)
    }

    const pct = Math.min(100, context.percent)
    const guard = (await $.state.get(GUARD).catch(() => undefined))?.value
    const { Box, Text } = $.ui.resolve(e)

    return (
      <Box>
        <Text dimColor>{short(model)} | </Text>
        <Text color={color(pct)}>{CIRCLES[Math.min(4, Math.round(pct / 25))]}</Text>
        <Text dimColor> {Math.round(pct)}% of {size(context.window)} | </Text>
        {guard?.ok && guard.enabled === false ? (
          <Text color="yellow">🔓 off</Text>
        ) : (
          <Text color={guard?.ok ? 'green' : 'red'}>{guard?.ok ? '🔒' : '🔓'}</Text>
        )}
        {guard?.masked ? <Text dimColor> {guard.masked}</Text> : null}
      </Box>
    )
  })
}
