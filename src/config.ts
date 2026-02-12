import { createHash } from 'crypto'
import { createRequire } from 'module'
import type { NextAuthConfig } from 'next-auth'

import { dataOpsClient } from './dataops-client'
import { getAuthSecret, shouldTrustHost } from './env'
import { AuthenticationServiceError, MetadataValidationError } from './errors'
import { logSecurityEvent } from './security-logger'
import type {
  AuthenticatedUser,
  AuthProviderCatalogEntry,
  OAuthProviderCatalogEntry,
  SessionToken,
} from './types'

function loadCredentialsProvider() {
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

const Credentials = loadCredentialsProvider()
type NextAuthProvider = ReturnType<typeof Credentials>

const providerCache: NextAuthProvider[] = []
let providersLoaded = false
let providersLoading: Promise<void> | null = null

async function ensureProvidersLoaded(): Promise<void> {
  if (providersLoaded) return
  if (providersLoading) {
    await providersLoading
    return
  }
  providersLoading = (async () => {
    const assembled: NextAuthProvider[] = []
    assembled.push(createCredentialsProvider())
    try {
      const external = await loadExternalProviders()
      if (Array.isArray(external) && external.length) {
        assembled.push(...external)
      }
    } catch (err) {
      console.warn('[ux/auth] Failed to load external providers', err)
    }
    assembled.push(createGuestProvider())
    providerCache.splice(0, providerCache.length, ...assembled)
    providersLoaded = true
  })()
  await providersLoading
}

function createGuestProvider(): NextAuthProvider {
  return Credentials({
    id: 'guest',
    name: 'Guest Account',
    credentials: {},
    async authorize() {
      const user = await resolveGuestUser()
      return {
        id: user.id,
        email: user.email,
        name: user.name ?? undefined,
        image: user.image ?? undefined,
        roles: user.roles,
        groups: user.groups,
        tenantId: user.tenantId,
        metadata: user.metadata ?? {},
      }
    },
  })
}

async function resolveGuestUser(): Promise<AuthenticatedUser> {
  const email = getGuestEmail()

  // First, try to fetch existing guest user from DataOps
  try {
    const existing = await dataOpsClient.getUserByEmail(email)
    if (existing) {
      return normaliseGuestUser(existing)
    }
  } catch (err) {
    // Log warning but continue - we'll try to create the user next
    console.warn(`[ux/auth] Failed to load guest account ${email} from DataOps`, err)
  }

  // Prepare the guest user template for creation
  const guestTemplate: AuthenticatedUser = {
    id: deriveGuestUserId(email),
    email,
    name: getGuestName(),
    image: null,
    roles: ['guest'],
    groups: [],
    tenantId: null,
    metadata: { accountType: 'guest', managedBy: 'cms-login' },
  }

  // SECURITY CRITICAL: Attempt to ensure user exists in DataOps
  // If this fails, we MUST NOT use a local template as this bypasses
  // proper authentication and authorization checks.
  try {
    const ensured = await dataOpsClient.ensureUser(guestTemplate)
    return normaliseGuestUser(ensured)
  } catch (err) {
    // Log security event before throwing
    logSecurityEvent(
      'guest_resolution_failure',
      'Failed to ensure guest account in DataOps service',
      err,
      { email, guestUserId: guestTemplate.id },
    )

    // Throw error to prevent bypass of authentication
    throw new AuthenticationServiceError(
      'Guest account resolution failed: DataOps service unavailable',
      { email, originalError: err instanceof Error ? err.message : String(err) },
    )
  }
}

function getGuestEmail(): string {
  return (process.env.AMI_GUEST_EMAIL || 'guest@ami.local').toLowerCase()
}

function getGuestName(): string {
  return process.env.AMI_GUEST_NAME || 'Guest AMI Account'
}

function createCredentialsProvider(): NextAuthProvider {
  return Credentials({
    id: 'credentials',
    name: 'AMI Credentials',
    credentials: {
      email: {
        type: 'email',
        label: 'Email',
      },
      password: {
        type: 'password',
        label: 'Password',
      },
    },
    async authorize(credentials: Record<string, string> | undefined) {
      if (!credentials?.email || !credentials?.password) {
        throw new Error('Email and password are required')
      }
      const email = credentials.email.toLowerCase()
      const verification = await dataOpsClient.verifyCredentials({
        email,
        password: credentials.password,
      })
      if (!verification.user) {
        return null
      }
      const ensured = await dataOpsClient.ensureUser(verification.user)
      return {
        id: ensured.id,
        email: ensured.email,
        name: ensured.name ?? undefined,
        image: ensured.image ?? undefined,
        roles: ensured.roles,
        groups: ensured.groups,
        tenantId: ensured.tenantId,
        metadata: ensured.metadata ?? {},
      }
    },
  })
}

async function loadExternalProviders(): Promise<NextAuthProvider[]> {
  const results: NextAuthProvider[] = []
  let catalog: AuthProviderCatalogEntry[] = []
  try {
    catalog = await dataOpsClient.getAuthProviderCatalog()
  } catch (err) {
    console.warn('[ux/auth] Failed to load provider catalog from DataOps', err)
  }

  if (!catalog.length) {
    catalog = collectEnvOAuthProviders()
  }

  const seen = new Set<string>()
  for (const entry of catalog) {
    if (entry.mode !== 'oauth') {
      continue
    }
    const key = entry.id || entry.providerType
    if (seen.has(key)) continue
    const provider = buildOAuthProvider(entry)
    if (provider) {
      seen.add(key)
      results.push(provider)
    }
  }

  return results
}

function buildOAuthProvider(entry: OAuthProviderCatalogEntry): NextAuthProvider | null {
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

function mergeAuthorization(entry: OAuthProviderCatalogEntry): { url?: string; params?: Record<string, string> } | undefined {
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

function collectEnvOAuthProviders(): OAuthProviderCatalogEntry[] {
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

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value)
}

function deriveGuestUserId(email: string): string {
  const digest = createHash('sha256').update(email).digest('hex')
  return `guest-${digest.slice(0, 24)}`
}

/**
 * Reads a string value from metadata with optional validation
 *
 * @param source - The metadata object to read from
 * @param key - The metadata key to read
 * @param defaultValue - Default value if key is missing or invalid
 * @param options - Additional options for validation
 * @returns The metadata value or defaultValue
 * @throws MetadataValidationError if field is required but missing/invalid
 */
function readMetadataString(
  source: Record<string, unknown> | undefined,
  key: string,
  defaultValue: string,
  options?: { required?: boolean; context?: Record<string, unknown> },
): string {
  if (!source && options?.required) {
    logSecurityEvent(
      'metadata_validation_failure',
      `Required metadata field '${key}' is missing: metadata source is undefined`,
      undefined,
      { key, ...options.context },
    )
    throw new MetadataValidationError(key, 'metadata source is undefined', options.context)
  }

  if (!source) return defaultValue

  const value = source[key]

  if (typeof value !== 'string' || !value.trim()) {
    if (options?.required) {
      logSecurityEvent(
        'metadata_validation_failure',
        `Required metadata field '${key}' is missing or invalid`,
        undefined,
        { key, valueType: typeof value, hasValue: value !== undefined, ...options.context },
      )
      throw new MetadataValidationError(
        key,
        value === undefined ? 'field is undefined' : `field has invalid type: ${typeof value}`,
        options.context,
      )
    }
    return defaultValue
  }

  return value
}

function normaliseGuestUser(payload: AuthenticatedUser | null): AuthenticatedUser {
  if (!payload) {
    throw new MetadataValidationError('user', 'Cannot normalize null user payload')
  }

  if (!payload.id || !payload.id.trim()) {
    throw new MetadataValidationError('id', 'User payload missing required field')
  }

  if (!payload.email || !payload.email.trim()) {
    throw new MetadataValidationError('email', 'User payload missing required field')
  }

  if (!Array.isArray(payload.groups)) {
    throw new MetadataValidationError('groups', 'User payload has invalid groups field (must be array)')
  }

  const email = payload.email.toLowerCase()
  const ensuredRoles = Array.from(new Set([...(payload.roles ?? []), 'guest']))
  const metadataBase = (payload.metadata && isRecord(payload.metadata) ? payload.metadata : {}) as Record<string, unknown>

  return {
    id: payload.id.trim(),
    email,
    name: payload.name ?? null,
    image: payload.image ?? null,
    roles: ensuredRoles,
    groups: payload.groups,
    tenantId: payload.tenantId ?? null,
    metadata: {
      ...metadataBase,
      accountType: readMetadataString(metadataBase, 'accountType', 'guest'),
      managedBy: readMetadataString(metadataBase, 'managedBy', 'cms-login'),
    },
  }
}

function mapToSessionToken(user: AuthenticatedUser): SessionToken {
  return {
    userId: user.id,
    email: user.email,
    name: user.name ?? null,
    image: user.image ?? null,
    roles: user.roles,
    groups: user.groups,
    tenantId: user.tenantId ?? null,
    metadata: user.metadata ?? {},
  }
}

type MutableToken = Record<string, unknown>
type MutableSession = { user?: Record<string, unknown> } & Record<string, unknown>

export async function loadAuthConfig(): Promise<NextAuthConfig> {
  await ensureProvidersLoaded()
  return {
    secret: getAuthSecret(),
    trustHost: shouldTrustHost(),
    session: {
      strategy: 'jwt',
      maxAge: 60 * 60 * 12, // 12 hours
    },
    pages: {
      signIn: '/auth/signin',
      error: '/auth/error',
    },
    providers: providerCache,
    callbacks: {
      async signIn(args: any) {
        const candidate = args?.user as { email?: string | null } | undefined
        if (!candidate?.email) return false
        return true
      },
      async jwt(args: any) {
        const token = args.token as MutableToken
        const user = args.user as unknown
        if (user) {
          const mapped = mapToSessionToken(user as AuthenticatedUser)
          token.sub = mapped.userId
          token.email = mapped.email
          token.name = mapped.name ?? undefined
          token.picture = mapped.image ?? undefined
          token.roles = mapped.roles
          token.groups = mapped.groups
          token.tenantId = mapped.tenantId ?? undefined
          token.metadata = mapped.metadata ?? {}
        }
        return token
      },
      async session(args: any) {
        const session = args.session as MutableSession
        const token = args.token as MutableToken
        session.user = {
          id: (token.sub as string | undefined) ?? '',
          email: (token.email as string | undefined) ?? '',
          name: (token.name as string | null | undefined) ?? null,
          image: (token.picture as string | null | undefined) ?? null,
          roles: Array.isArray(token.roles) ? (token.roles as string[]) : [],
          groups: Array.isArray(token.groups) ? (token.groups as string[]) : [],
          tenantId: (token.tenantId as string | null | undefined) ?? null,
          metadata: (token.metadata as Record<string, unknown> | undefined) ?? {},
        }
        return session as unknown as import('next-auth').Session
      },
    },
    events: {
      async signOut(message: any) {
        const token = message?.token as { sub?: string | null } | undefined
        console.info('[ux/auth] signOut', token?.sub)
      },
    },
  }
}

export async function getProviders(): Promise<NextAuthProvider[]> {
  await ensureProvidersLoaded()
  return providerCache.slice()
}

export function getCachedProviders(): NextAuthProvider[] {
  return providerCache.slice()
}
