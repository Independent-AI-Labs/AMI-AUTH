export type AuthEnvironment = {
  AUTH_SECRET?: string
  AUTH_TRUST_HOST?: boolean
  AUTH_CREDENTIALS_FILE?: string
  AUTH_ALLOWED_EMAILS?: string
  AUTH_PROVIDER_CATALOG_FILE?: string
}

let cachedEnv: AuthEnvironment | null = null

export function loadAuthEnvironment(): AuthEnvironment {
  if (cachedEnv) return cachedEnv
  const env = process.env
  const parsed: AuthEnvironment = {}

  if (typeof env.AUTH_SECRET === 'string') {
    if (env.AUTH_SECRET.length >= 32) parsed.AUTH_SECRET = env.AUTH_SECRET
    else console.warn('[ux/auth] AUTH_SECRET must be at least 32 characters long.')
  }

  if (typeof env.AUTH_TRUST_HOST === 'string') {
    parsed.AUTH_TRUST_HOST = env.AUTH_TRUST_HOST.toLowerCase() === 'true'
  }

  if (typeof env.AUTH_CREDENTIALS_FILE === 'string' && env.AUTH_CREDENTIALS_FILE.trim()) {
    parsed.AUTH_CREDENTIALS_FILE = env.AUTH_CREDENTIALS_FILE.trim()
  }

  if (typeof env.AUTH_ALLOWED_EMAILS === 'string' && env.AUTH_ALLOWED_EMAILS.trim()) {
    parsed.AUTH_ALLOWED_EMAILS = env.AUTH_ALLOWED_EMAILS.trim()
  }

  if (typeof env.AUTH_PROVIDER_CATALOG_FILE === 'string' && env.AUTH_PROVIDER_CATALOG_FILE.trim()) {
    parsed.AUTH_PROVIDER_CATALOG_FILE = env.AUTH_PROVIDER_CATALOG_FILE.trim()
  }

  cachedEnv = parsed
  return parsed
}

export function getAuthSecret(): string | undefined {
  return loadAuthEnvironment().AUTH_SECRET
}

export function getAllowedEmails(): string[] | null {
  const allowed = loadAuthEnvironment().AUTH_ALLOWED_EMAILS
  if (!allowed) return null
  return allowed
    .split(',')
    .map((part) => part.trim().toLowerCase())
    .filter(Boolean)
}

export function getCredentialsFile(): string | null {
  return loadAuthEnvironment().AUTH_CREDENTIALS_FILE ?? null
}

export function getProviderCatalogFile(): string | null {
  return loadAuthEnvironment().AUTH_PROVIDER_CATALOG_FILE ?? null
}

export function shouldTrustHost(): boolean {
  return loadAuthEnvironment().AUTH_TRUST_HOST ?? false
}
