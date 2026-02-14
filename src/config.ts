import type { NextAuthConfig } from 'next-auth'

import { authStore } from './auth-store'
import { getAuthSecret, shouldTrustHost } from './env'
import { MetadataValidationError } from './errors'
import {
  buildOAuthProvider,
  collectEnvOAuthProviders,
  deriveGuestUserId,
  isRecord,
  loadCredentialsProvider,
  type NextAuthProvider,
} from './providers'
import { logSecurityEvent } from './security-logger'
import type { AuthenticatedUser, AuthProviderCatalogEntry, SessionToken } from './types'

const Credentials = loadCredentialsProvider()

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

  // Try to fetch existing guest user from local credentials store
  try {
    const existing = await authStore.getUserByEmail(email)
    if (existing) {
      return normaliseGuestUser(existing)
    }
  } catch (err) {
    console.warn(`[ux/auth] Failed to load guest account ${email} from credentials store`, err)
  }

  // No existing record — return a local guest template
  const guest: AuthenticatedUser = {
    id: deriveGuestUserId(email),
    email,
    name: getGuestName(),
    image: null,
    roles: ['guest'],
    groups: [],
    tenantId: null,
    metadata: { accountType: 'guest', managedBy: 'cms-login' },
  }
  return normaliseGuestUser(guest)
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
      const verification = await authStore.verifyCredentials({
        email,
        password: credentials.password,
      })
      if (!verification.user) {
        return null
      }
      return {
        id: verification.user.id,
        email: verification.user.email,
        name: verification.user.name ?? undefined,
        image: verification.user.image ?? undefined,
        roles: verification.user.roles,
        groups: verification.user.groups,
        tenantId: verification.user.tenantId,
        metadata: verification.user.metadata ?? {},
      }
    },
  })
}

async function loadExternalProviders(): Promise<NextAuthProvider[]> {
  const results: NextAuthProvider[] = []
  let catalog: AuthProviderCatalogEntry[] = []
  try {
    catalog = await authStore.getAuthProviderCatalog()
  } catch (err) {
    console.warn('[ux/auth] Failed to load provider catalog', err)
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

/**
 * Reads a string value from metadata with optional validation
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
  const metadataBase = (payload.metadata && isRecord(payload.metadata) ? payload.metadata : {}) as Record<
    string,
    unknown
  >

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
