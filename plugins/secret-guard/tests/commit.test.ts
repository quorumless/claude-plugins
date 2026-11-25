import { expect, test } from 'claude-code/testing'

import { commitRange, findGitSend } from '../hooks/redact.ts'

// split so this file never holds a token-shaped string
const j = (...p: string[]) => p.join('')
const ghp = j('gh', 'p_', 'a1B2'.repeat(9))
const keyId = j('AK', 'IA', 'Q3EG', 'B7XK', 'M2PL', 'W4ZN')

// a repo whose `git diff` prints `diff`, a user who answers `answer`, and a record of what ran and was asked
const world = (on: any, diff: string, answer = 'Deny', exitCode = 0) => {
  const ran: string[][] = []
  const asked: string[] = []
  on('session.cwd', () => ({ value: '/proj' }))
  on('env.get', (_$: any, e: any) => ({ value: e.name === 'HOME' ? '/home/t' : undefined }))
  on('fs.read', () => { throw new Error('ENOENT') })
  on('process.run', (_$: any, e: any) => {
    ran.push(e.argv ?? e.command ?? e.args ?? e)
    return { value: { exitCode, stdout: diff, stderr: '' } }
  })
  on('tool.call', (_$: any, e: any) => {
    if (e.tool === 'AskUserQuestion') {
      const q = e.questions[0].question
      asked.push(q)
      return { result: { questions: e.questions, answers: { [q]: answer } } }
    }
    return { result: { stdout: 'ran', stderr: '', interrupted: false } }
  })
  return { ran, asked }
}
const patch = (file: string, ...lines: string[]) =>
  `diff --git a/${file} b/${file}\n--- a/${file}\n+++ b/${file}\n@@ -0,0 +7,${lines.length} @@\n${lines.map(l => `+${l}`).join('\n')}\n`

test('fix 11: a leaking commit asks, naming the placeholder and file:line, and a Deny blocks it', async ($, on) => {
  const { asked } = world(on, patch('src/app.ts', 'const a = 1', `const t = "${ghp}"`))
  const r: any = await $.tool.call({ tool: 'Bash', command: 'git commit -m "add app"' } as any)
  expect(asked.length).toBe(1)
  expect(asked[0]).toContain('src/app.ts:8')
  expect(asked[0]).toContain('$SECRET_')
  expect(asked[0]).not.toContain(ghp)
  expect(JSON.stringify(r)).toContain('user denied')
})

test('fix 11: Allow lets the commit through', async ($, on) => {
  const { asked, ran } = world(on, patch('src/app.ts', `const t = "${ghp}"`), 'Allow')
  const r: any = await $.tool.call({ tool: 'Bash', command: 'git -C /proj commit -m "add app" -- src/app.ts' } as any)
  expect(JSON.stringify(ran)).toContain('["git","-C","/proj","diff","--unified=0","HEAD","--","src/app.ts"]')
  expect(asked.length).toBe(1)
  expect(JSON.stringify(r)).not.toContain('denied')
})

test('fix 11: "git commit" inside a message or an echo is not a commit', async ($, on) => {
  const { ran } = world(on, patch('a.ts', `x = "${ghp}"`))
  await $.tool.call({ tool: 'Bash', command: 'echo "next: git commit and push"' } as any)
  await $.tool.call({ tool: 'Bash', command: 'grep -r "git push" docs/' } as any)
  expect(ran.length).toBe(0)
})

test('fix 11: cz commit is checked', async ($, on) => {
  const { asked } = world(on, patch('a.ts', `x = "${ghp}"`))
  await $.tool.call({ tool: 'Bash', command: 'cd /proj && cz commit' } as any)
  expect(asked.length).toBe(1)
})

test('fix 11: a lone AWS key id does not ask; with its secret it does', async ($, on) => {
  const { asked, ran } = world(on, patch('main.tf', `access_key = "${keyId}"`))
  await $.tool.call({ tool: 'Bash', command: 'git commit -m x' } as any)
  expect(JSON.stringify(ran)).toContain('"diff"') // the diff was checked, not skipped
  expect(asked.length).toBe(0)
})

test('fix 11: an AWS key id with its secret asks', async ($, on) => {
  const secret = j('h7Fq2', 'LmX9p', 'RtKw3', 'Zb8Vn', 'C4yDa', '1sE6u', 'J0oGi', 'T5rQ/')
  const { asked } = world(on, patch('creds', `aws_access_key_id = ${keyId}`, j('aws_secret_', 'access_key = ', secret)))
  await $.tool.call({ tool: 'Bash', command: 'git commit -m x' } as any)
  expect(asked.length).toBe(1)
})

test('fix 11: commitRange reads flags outside the message and explicit paths', () => {
  expect(commitRange(' -m "add a feature" ')).toEqual(['--cached'])
  expect(commitRange(' -m "fix -a flag handling"')).toEqual(['--cached'])
  expect(commitRange(" -m 'use --all now'")).toEqual(['--cached'])
  expect(commitRange(' -am "msg"')).toEqual(['HEAD'])
  expect(commitRange(' -a -m msg')).toEqual(['HEAD'])
  expect(commitRange(' --only src/a.ts -m "msg"')).toEqual(['HEAD', '--', 'src/a.ts'])
  expect(commitRange(' -m "msg" -- a.ts b.ts')).toEqual(['HEAD', '--', 'a.ts', 'b.ts'])
  expect(commitRange(' --amend --no-edit && git push')).toEqual(['--cached'])
  expect(commitRange(' -m "msg" -- "my file.ts"')).toEqual(['HEAD'])
  expect(commitRange(' "my file.ts" -m x')).toEqual(['HEAD'])
})

test('fix 11: commit/push is found behind every shell prefix', () => {
  for (const c of [
    '(git commit -m x)', '{ git commit; }', 'X=1 git commit', 'env X=1 git commit', 'env -i X=1 git push', '/usr/bin/git commit',
    'sudo git commit', 'time git push', 'command git commit', 'nohup git commit', 'exec git commit', 'git --no-pager commit',
    'git --git-dir=../r/.git commit', "bash -c 'git commit -m x'", 'sh -c "cd /a && git push"', 'uv run cz commit', 'cz c',
    'git -c user.name=x commit', 'cd /proj && git -C sub push', 'ls; git commit -am "msg"',
  ]) expect(findGitSend(c)).toBeDefined()
  for (const c of [
    'echo "git commit"', 'git log --grep "git commit"', 'grep -r "; git push" docs', 'git commit-tree x', "echo 'cz commit'",
    'git status', 'gitk commit',
  ]) expect(findGitSend(c)).toBeUndefined()
  expect(findGitSend('git -C "/my dir" commit -a')?.dir).toBe('"/my dir"')
  expect(findGitSend('uv run cz c')?.cz).toBe(true)
  expect(findGitSend('time git push origin x')?.kind).toBe('push')
})

test('fix 11: a commit whose diff fails asks instead of passing unchecked', async ($, on) => {
  const { asked } = world(on, '', 'Deny', 128)
  const r: any = await $.tool.call({ tool: 'Bash', command: 'git commit -m x' } as any)
  expect(asked[0]).toContain('could not check')
  expect(JSON.stringify(r)).toContain('user denied')
})
