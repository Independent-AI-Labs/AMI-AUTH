import { readFile, stat as statFile } from 'fs/promises'
import path from 'path'
import { scryptSync, timingSafeEqual, createHash, randomUUID } from 'crypto'

import {
  getAllowedEmails,
  getCredentialsFile,
  getDataOpsAuthUrl,
  getInternalToken,
  getProviderCatalogFile,
} from './env'
import type {
  AuthenticatedUser,
  CredentialsPayload,
  DataOpsCredentialRecord,
  AuthProviderCatalogEntry,
  VerifyCredentialsResponse,
} from './types'

const DEFAULT_SCRYPT_KEYLEN = 64

class LocalCredentialsStore {
  private cache: { mtimeMs: number; records: DataOpsCredentialRecord[] } | null = null

  constructor(private readonly filePath: string) {}

  async load(): Promise<DataOpsCredentialRecord[]> {
    const abs = path.resolve(process.cwd(), this.filePath)
    const stat = await statFile(abs).catch(() => null)
    if (!stat) return []

    if (this.cache && Math.abs(this.cache.mtimeMs - stat.mtimeMs) < 1) {
      return this.cache.records
    }

    const raw = await readFile(abs, 'utf8')
    const parsed = JSON.parse(raw)
    if (!Array.isArray(parsed)) return []
    const allowed = getAllowedEmails()
    const records = parsed
      .filter((entry) => entry && typeof entry.email === 'string')
      .map((entry) => ({
        ...entry,
        email: String(entry.email).toLowerCase(),
        roles: Array.isArray(entry.roles) ? entry.roles.map(String) : [],
        groups: Array.isArray(entry.groups) ? entry.groups.map(String) : [],
        tenantId: entry.tenantId ? String(entry.tenantId) : null,
      }))
      .filter((record) => !allowed || allowed.includes(record.email))

    this.cache = { mtimeMs: stat.mtimeMs, records }
    return records
  }

  async verifyCredentials(payload: CredentialsPayload): Promise<VerifyCredentialsResponse> {
    const records = await this.load()
    const entry = records.find((record) => record.email === payload.email.toLowerCase())
    if (!entry) return { user: null, reason: 'not_found' }
    const ok = await verifyPassword(payload.password, entry.password)
    if (!ok) return { user: null, reason: 'invalid_password' }

    const id = entry.id ?? deriveStableId(entry.email)
    const user: AuthenticatedUser = {
      id,
      email: entry.email,
      name: entry.name ?? null,
      image: entry.image ?? null,
      roles: entry.roles ?? [],
      groups: entry.groups ?? [],
      tenantId: entry.tenantId ?? null,
      metadata: entry.metadata ?? {},
    }
    return { user }
  }

  async getUserByEmail(email: string): Promise<AuthenticatedUser | null> {
    const records = await this.load()
    const entry = records.find((record) => record.email === email.toLowerCase())
    if (!entry) return null
    return {
      id: entry.id ?? deriveStableId(entry.email),
      email: entry.email,
      name: entry.name ?? null,
      image: entry.image ?? null,
      roles: entry.roles ?? [],
      groups: entry.groups ?? [],
      tenantId: entry.tenantId ?? null,
      metadata: entry.metadata ?? {},
    }
  }
}

class LocalProviderCatalogStore {
  private cache: { mtimeMs: number; entries: AuthProviderCatalogEntry[] } | null = null

  constructor(private readonly filePath: string) {}

  async load(): Promise<AuthProviderCatalogEntry[]> {
    const abs = path.resolve(process.cwd(), this.filePath)
    const stat = await statFile(abs).catch(() => null)
    if (!stat) return []

    if (this.cache && Math.abs(this.cache.mtimeMs - stat.mtimeMs) < 1) {
      return this.cache.entries
    }

    const raw = await readFile(abs, 'utf8').catch(() => '')
    if (!raw) return []

    const parsed = safeParseCatalog(raw)
    this.cache = { mtimeMs: stat.mtimeMs, entries: parsed }
    return parsed
  }
}

function deriveStableId(email: string): string {
  const digest = createHash('sha256').update(email).digest('hex')
  return `local-${digest.slice(0, 24)}`
}

async function verifyPassword(password: string, descriptor: string): Promise<boolean> {
  if (!descriptor) return false
  if (descriptor.startsWith('scrypt:')) {
    const [, saltB64, keyB64] = descriptor.split(':')
    if (!saltB64 || !keyB64) return false
    const key = Buffer.from(keyB64, 'base64')
    const derived = scryptSync(password, Buffer.from(saltB64, 'base64'), key.length || DEFAULT_SCRYPT_KEYLEN)
    return timingSafeEqual(key, derived)
  }
  if (descriptor.startsWith('plain:')) {
    return timingSafeEqual(Buffer.from(descriptor.slice('plain:'.length)), Buffer.from(password))
  }
  // Default comparison
  return timingSafeEqual(Buffer.from(descriptor), Buffer.from(password))
}

async function requestJSON<T>(input: RequestInfo, init?: RequestInit): Promise<T> {
  const response = await fetch(input, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...(init?.headers || {}),
    },
  })
  if (!response.ok) {
    const text = await response.text().catch(() => response.statusText)
    throw new Error(`DataOps request failed: ${response.status} ${text}`)
  }
  return response.json() as Promise<T>
}

export class DataOpsClient {
  private readonly baseUrl: URL | null
  private readonly token: string | null
  private readonly localStore: LocalCredentialsStore | null
  private readonly localCatalog: LocalProviderCatalogStore | null

  constructor() {
    this.baseUrl = getDataOpsAuthUrl()
    this.token = getInternalToken()
    const credentialsFile = getCredentialsFile()
    this.localStore = credentialsFile ? new LocalCredentialsStore(credentialsFile) : null
    const catalogFile = getProviderCatalogFile()
    this.localCatalog = catalogFile ? new LocalProviderCatalogStore(catalogFile) : null
  }

  private makeUrl(pathname: string): string {
    if (!this.baseUrl) throw new Error('DATAOPS_AUTH_URL not configured')
    const url = new URL(pathname, this.baseUrl)
    return url.toString()
  }

  private authHeaders(): Record<string, string> {
    if (!this.token) return {}
    return { Authorization: `Bearer ${this.token}` }
  }

  async verifyCredentials(payload: CredentialsPayload): Promise<VerifyCredentialsResponse> {
    if (this.baseUrl) {
      try {
        return await requestJSON<VerifyCredentialsResponse>(this.makeUrl('/auth/verify'), {
          method: 'POST',
          headers: this.authHeaders(),
          body: JSON.stringify(payload),
        })
      } catch (err) {
        console.error('[ux/auth] Remote credential verification failed, using local store', err)
      }
    }

    if (this.localStore) {
      return this.localStore.verifyCredentials(payload)
    }

    return { user: null, reason: 'unconfigured' }
  }

  async getUserByEmail(email: string): Promise<AuthenticatedUser | null> {
    if (this.baseUrl) {
      try {
        const result = await requestJSON<{ user: AuthenticatedUser | null }>(
          this.makeUrl(`/auth/users/by-email?email=${encodeURIComponent(email)}`),
          {
            method: 'GET',
            headers: this.authHeaders(),
            cache: 'no-store',
          },
        )
        if (result.user) {
          return result.user
        }
      } catch (err) {
        console.error('[ux/auth] Remote getUserByEmail failed, using local store', err)
      }
    }

    if (this.localStore) {
      return this.localStore.getUserByEmail(email)
    }

    return null
  }

  async getUserById(id: string): Promise<AuthenticatedUser | null> {
    if (this.baseUrl) {
      try {
        const result = await requestJSON<{ user: AuthenticatedUser | null }>(
          this.makeUrl(`/auth/users/${encodeURIComponent(id)}`),
          {
            method: 'GET',
            headers: this.authHeaders(),
            cache: 'no-store',
          },
        )
        if (result.user) return result.user
      } catch (err) {
        console.error('[ux/auth] Remote getUserById failed, using local store', err)
      }
    }

    if (!this.localStore) return null
    const records = await this.localStore.load()
    const match = records.find((record) => (record.id ?? deriveStableId(record.email)) === id)
    if (!match) return null
    return {
      id,
      email: match.email,
      name: match.name ?? null,
      image: match.image ?? null,
      roles: match.roles ?? [],
      groups: match.groups ?? [],
      tenantId: match.tenantId ?? null,
      metadata: match.metadata ?? {},
    }
  }

  async ensureUser(user: AuthenticatedUser): Promise<AuthenticatedUser> {
    if (this.baseUrl) {
      try {
        const result = await requestJSON<{ user: AuthenticatedUser }>(this.makeUrl('/auth/users'), {
          method: 'POST',
          headers: {
            ...this.authHeaders(),
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(user),
        })
        return result.user
      } catch (err) {
        console.error('[ux/auth] Failed to upsert user in DataOps', err)
      }
    }

    // Local mode simply returns the provided user
    if (!user.id) {
      return { ...user, id: user.email ? deriveStableId(user.email) : randomUUID() }
    }
    return user
  }

  async getAuthProviderCatalog(): Promise<AuthProviderCatalogEntry[]> {
    if (this.baseUrl) {
      try {
        const response = await requestJSON<unknown>(this.makeUrl('/auth/providers/catalog'), {
          method: 'GET',
          headers: this.authHeaders(),
          cache: 'no-store',
        })
        const parsed = normaliseCatalogResponse(response)
        if (parsed.length) {
          return parsed
        }
      } catch (err) {
        console.error('[ux/auth] Failed to fetch provider catalog from DataOps', err)
      }
    }

    if (this.localCatalog) {
      return this.localCatalog.load()
    }

    return []
  }
}

export const dataOpsClient = new DataOpsClient()

function safeParseCatalog(raw: string): AuthProviderCatalogEntry[] {
  try {
    const parsed = JSON.parse(raw)
    return normaliseCatalogResponse(parsed)
  } catch (err) {
    console.warn('[ux/auth] Failed to parse local provider catalog file', err)
    return []
  }
}

function normaliseCatalogResponse(input: unknown): AuthProviderCatalogEntry[] {
  const entries: AuthProviderCatalogEntry[] = []
  const items = Array.isArray(input)
    ? input
    : input && typeof input === 'object' && 'providers' in input && Array.isArray((input as any).providers)
      ? (input as any).providers
      : []

  for (const candidate of items) {
    const parsed = normaliseCatalogEntry(candidate)
    if (parsed) entries.push(parsed)
  }

  return entries
}

function normaliseCatalogEntry(candidate: unknown): AuthProviderCatalogEntry | null {
  if (!candidate || typeof candidate !== 'object') return null
  const raw = candidate as Record<string, unknown>
  const mode = String(raw.mode ?? 'oauth').toLowerCase()
  if (mode !== 'oauth') {
    // Only OAuth providers integrate directly with NextAuth today.
    return null
  }

  const providerType = String(raw.providerType ?? raw.provider_type ?? raw.type ?? '').toLowerCase()
  const clientId = valueToString(raw.clientId ?? raw.client_id)
  const clientSecret = valueToString(raw.clientSecret ?? raw.client_secret)

  if (!providerType || !clientId || !clientSecret) {
    return null
  }

  const id = valueToString(raw.id) || providerType
  const scopes = Array.isArray(raw.scopes) ? raw.scopes.map((scope) => String(scope)) : undefined
  const tenant = raw.tenant ? String(raw.tenant) : raw.tenantId ? String(raw.tenantId) : undefined
  const allowDangerous = Boolean(
    raw.allowDangerousEmailAccountLinking ?? raw.allow_dangerous_email_account_linking ??
      (raw.flags && typeof raw.flags === 'object' && 'allowDangerousEmailAccountLinking' in (raw.flags as any)
        ? (raw.flags as Record<string, unknown>).allowDangerousEmailAccountLinking
        : false),
  )

  const authorization = parseNestedRecord(raw.authorization ?? raw.authorizationUrl ?? raw.authorization_url)
  const token = parseNestedRecord(raw.token ?? raw.tokenUrl ?? raw.token_url)
  const userInfo = parseNestedRecord(raw.userInfo ?? raw.userInfoUrl ?? raw.user_info_url)
  const wellKnown = valueToString(raw.wellKnown ?? raw.well_known ?? raw.wellKnownUrl ?? raw.well_known_url)
  const displayName = valueToString(raw.displayName ?? raw.name)
  const metadata = raw.metadata && typeof raw.metadata === 'object' ? (raw.metadata as Record<string, unknown>) : undefined

  return {
    id,
    providerType: providerType as AuthProviderCatalogEntry['providerType'],
    mode: 'oauth',
    clientId,
    clientSecret,
    displayName: displayName || undefined,
    scopes,
    tenant: tenant ?? null,
    authorization,
    token,
    userInfo,
    flags: allowDangerous ? { allowDangerousEmailAccountLinking: true } : undefined,
    wellKnown: wellKnown || undefined,
    metadata,
  }
}

function parseNestedRecord(value: unknown): { url?: string; params?: Record<string, string> } | undefined {
  if (!value) return undefined
  if (typeof value === 'string') {
    return { url: value }
  }
  if (typeof value !== 'object') return undefined
  const record = value as Record<string, unknown>
  const url = valueToString(record.url)
  const params = record.params && typeof record.params === 'object'
    ? Object.fromEntries(
        Object.entries(record.params as Record<string, unknown>)
          .filter(([key, val]) => typeof val === 'string')
          .map(([key, val]) => [key, String(val)]),
      )
    : undefined
  const result: { url?: string; params?: Record<string, string> } = {}
  if (url) result.url = url
  if (params && Object.keys(params).length) result.params = params
  return Object.keys(result).length ? result : undefined
}

function valueToString(input: unknown): string {
  return typeof input === 'string' ? input.trim() : typeof input === 'number' ? String(input) : ''
}
