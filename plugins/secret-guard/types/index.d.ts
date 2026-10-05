// read by the context-status mod for its lock icon
export type SecretGuardHealth = { ok: boolean; masked: number; enabled: boolean }

declare module 'claude-code' {
  interface PluginState {
    'secret-guard': { health: SecretGuardHealth }
  }
}
