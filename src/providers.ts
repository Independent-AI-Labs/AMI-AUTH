import { createHash } from 'crypto'
import { createRequire } from 'module'

import type { OAuthProviderCatalogEntry } from './types'

export function loadCredentialsProvider() {
  try {
    const require = createRequire(import.meta.url)
    const mod = require('next-auth/providers/credentials')
    return (mod as any).default ?? mod
  } catch (err) {
    console.warn('[ux/auth] next-auth credentials provider unavailable, using dev provider.', err)
    return function devCredentials(options: any) {
      return {
        id: 'credentials',
        name: 'Credentials',
        type: 'credentials',
        authorize: options.authorize,
        credentials: options.credentials ?? {},
      }
    }
  }
}

export type NextAuthProvider = ReturnType<ReturnType<typeof loadCredentialsProvider>>

export function buildOAuthProvider(
  entry: OAuthProviderCatalogEntry,
): NextAuthProvider | null {
  const loader = resolveProviderLoader(entry)
  if (!loader) return null

  const baseOptions: Record<string, unknown> = {
    id: entry.id || defaultProviderId(entry.providerType),
    name: entry.displayName ?? defaultProviderName(entry.providerType),
    clientId: entry.clientId,
    clientSecret: entry.clientSecret,
  }

  const authorization = mergeAuthorization(entry)
  if (authorization) baseOptions.authorization = authorization
  if (entry.token?.url) baseOptions.token = { url: entry.token.url }
  if (entry.userInfo?.url) baseOptions.userinfo = { url: entry.userInfo.url }
  if (entry.flags?.allowDangerousEmailAccountLinking) {
    baseOptions.allowDangerousEmailAccountLinking = true
  }
  if (entry.wellKnown) {
    baseOptions.wellKnown = entry.wellKnown
  }

  if (entry.providerType === 'azure_ad') {
    if (entry.tenant) baseOptions.tenantId = entry.tenant
    if (entry.metadata && isRecord(entry.metadata) && entry.metadata.authority) {
      baseOptions.authority = entry.metadata.authority
    }
  }

  if (entry.providerType === 'oauth2' && entry.metadata && isRecord(entry.metadata)) {
    const profile = entry.metadata.profile
    if (profile && isRecord(profile)) {
      const idField = typeof profile.id === 'string' ? profile.id : 'sub'
      const emailField = typeof profile.email === 'string' ? profile.email : 'email'
      const nameField = typeof profile.name === 'string' ? profile.name : 'name'
      const imageField = typeof profile.image === 'string' ? profile.image : 'picture'
      baseOptions.profile = (raw: Record<string, unknown>) => ({
        id: String(raw[idField] ?? raw.sub ?? ''),
        email: raw[emailField] ? String(raw[emailField]) : undefined,
        name: raw[nameField] ? String(raw[nameField]) : undefined,
        image: raw[imageField] ? String(raw[imageField]) : undefined,
      })
    }
    if (Array.isArray(entry.metadata.checks)) {
      baseOptions.checks = entry.metadata.checks
    }
  }

  try {
    return loader(baseOptions)
  } catch (err) {
    console.error(`[ux/auth] Failed to initialise ${entry.providerType} provider`, err)
    return null
  }
}

function resolveProviderLoader(entry: OAuthProviderCatalogEntry) {
  const moduleName = providerModuleFor(entry.providerType)
  if (!moduleName) {
    console.warn(`[ux/auth] Unsupported provider type: ${entry.providerType}`)
    return null
  }
  const loader = loadProviderModule(moduleName)
  if (!loader) {
    console.warn(`[ux/auth] next-auth provider module not available for ${entry.providerType}`)
    return null
  }
  return loader
}

const providerModuleCache: Record<string, any | null> = {}

function loadProviderModule(moduleName: string) {
  if (moduleName in providerModuleCache) {
    return providerModuleCache[moduleName]
  }
  try {
    const require = createRequire(import.meta.url)
    const mod = require(`next-auth/providers/${moduleName}`)
    const resolved = (mod as any).default ?? mod
    providerModuleCache[moduleName] = resolved
    return resolved
  } catch (err) {
    console.warn(`[ux/auth] next-auth/providers/${moduleName} not found`, err)
    providerModuleCache[moduleName] = null
    return null
  }
}

function providerModuleFor(type: OAuthProviderCatalogEntry['providerType']): string | null {
  switch (type) {
    case 'google':
      return 'google'
    case 'github':
      return 'github'
    case 'azure_ad':
      return 'azure-ad'
    case 'oauth2':
      return 'oauth'
    default:
      return null
  }
}

function mergeAuthorization(
  entry: OAuthProviderCatalogEntry,
): { url?: string; params?: Record<string, string> } | undefined {
  const params: Record<string, string> = {}
  if (entry.scopes?.length) {
    params.scope = entry.scopes.join(' ')
  }
  if (entry.authorization?.params) {
    Object.assign(params, entry.authorization.params)
  }
  const auth: { url?: string; params?: Record<string, string> } = {}
  if (entry.authorization?.url) {
    auth.url = entry.authorization.url
  }
  if (Object.keys(params).length) {
    auth.params = params
  }
  return Object.keys(auth).length ? auth : undefined
}

function defaultProviderId(type: OAuthProviderCatalogEntry['providerType']): string {
  switch (type) {
    case 'azure_ad':
      return 'azure-ad'
    default:
      return type
  }
}

function defaultProviderName(type: OAuthProviderCatalogEntry['providerType']): string {
  switch (type) {
    case 'google':
      return 'Google Workspace'
    case 'github':
      return 'GitHub'
    case 'azure_ad':
      return 'Microsoft Entra ID'
    case 'oauth2':
      return 'OAuth 2.0'
    default:
      return type.replace(/_/g, ' ').toUpperCase()
  }
}

export function collectEnvOAuthProviders(): OAuthProviderCatalogEntry[] {
  const env = process.env
  const entries: OAuthProviderCatalogEntry[] = []

  if (env.GOOGLE_CLIENT_ID && env.GOOGLE_CLIENT_SECRET) {
    entries.push({
      id: 'google',
      providerType: 'google',
      mode: 'oauth',
      clientId: env.GOOGLE_CLIENT_ID,
      clientSecret: env.GOOGLE_CLIENT_SECRET,
      scopes: parseScopes(env.GOOGLE_SCOPES),
      flags: envBoolean(env.GOOGLE_ALLOW_DANGEROUS_EMAIL_LINKING)
        ? { allowDangerousEmailAccountLinking: true }
        : undefined,
    })
  }

  if (env.GITHUB_CLIENT_ID && env.GITHUB_CLIENT_SECRET) {
    entries.push({
      id: 'github',
      providerType: 'github',
      mode: 'oauth',
      clientId: env.GITHUB_CLIENT_ID,
      clientSecret: env.GITHUB_CLIENT_SECRET,
      scopes: parseScopes(env.GITHUB_SCOPES),
      flags: envBoolean(env.GITHUB_ALLOW_DANGEROUS_EMAIL_LINKING)
        ? { allowDangerousEmailAccountLinking: true }
        : undefined,
    })
  }

  if (env.AZURE_AD_CLIENT_ID && env.AZURE_AD_CLIENT_SECRET) {
    entries.push({
      id: 'azure-ad',
      providerType: 'azure_ad',
      mode: 'oauth',
      clientId: env.AZURE_AD_CLIENT_ID,
      clientSecret: env.AZURE_AD_CLIENT_SECRET,
      tenant: env.AZURE_AD_TENANT_ID ?? null,
      scopes: parseScopes(env.AZURE_AD_SCOPES),
      metadata: env.AZURE_AD_AUTHORITY ? { authority: env.AZURE_AD_AUTHORITY } : undefined,
      flags: envBoolean(env.AZURE_AD_ALLOW_DANGEROUS_EMAIL_LINKING)
        ? { allowDangerousEmailAccountLinking: true }
        : undefined,
    })
  }

  return entries
}

function parseScopes(value: string | undefined): string[] | undefined {
  if (!value) return undefined
  const scopes = value
    .split(/[,\s]+/g)
    .map((scope) => scope.trim())
    .filter(Boolean)
  return scopes.length ? scopes : undefined
}

function envBoolean(value: string | undefined): boolean {
  if (!value) return false
  return ['1', 'true', 'yes', 'on'].includes(value.toLowerCase())
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value)
}

export function deriveGuestUserId(email: string): string {
  const digest = createHash('sha256').update(email).digest('hex')
  return `guest-${digest.slice(0, 24)}`
}
