// secret-guard's state, read for the lock icon
declare module 'claude-code' {
  interface PluginState {
    'secret-guard': { health: { ok: boolean; masked: number; enabled?: boolean } }
  }
}
export {}
