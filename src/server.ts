import { createRequire } from 'module'
import { loadAuthConfig } from './config'

type AuthExports = {
  auth: (...args: any[]) => any
  handlers: { GET: (...args: any[]) => Promise<Response>; POST: (...args: any[]) => Promise<Response> }
  signIn: (...args: any[]) => Promise<any>
  signOut: (...args: any[]) => Promise<any>
}

function deriveDevUserId(email: string): string {
  const safeEmail = email.trim().toLowerCase()
  let hash = 0
  for (let i = 0; i < safeEmail.length; i += 1) {
    hash = (hash * 31 + safeEmail.charCodeAt(i)) >>> 0
  }
  const slug = hash.toString(36).padStart(8, '0')
  return `user-${slug}`
}

const DEV_SIGNOUT_COOKIE = 'ami-dev-signout'
const DEV_SIGNOUT_SET = `${DEV_SIGNOUT_COOKIE}=1; Path=/; SameSite=Lax`
const DEV_SIGNOUT_CLEAR = `${DEV_SIGNOUT_COOKIE}=; Max-Age=0; Path=/; SameSite=Lax`

function hasSignoutCookie(request: Request): boolean {
  const cookie = request.headers.get('cookie') || ''
  return cookie.split(';').some((c) => c.trim().startsWith(`${DEV_SIGNOUT_COOKIE}=1`))
}

async function isSignedOutFromHeaders(): Promise<boolean> {
  try {
    const { cookies } = await import('next/headers')
    const store = await cookies()
    return store.get(DEV_SIGNOUT_COOKIE)?.value === '1'
  } catch {
    return false
  }
}

function createDevAuth(): AuthExports {
  const guestEmail = (process.env.AMI_GUEST_EMAIL || 'guest@ami.local').toLowerCase()
  const guestName = process.env.AMI_GUEST_NAME || 'Guest AMI Account'
  const guestUserId = deriveDevUserId(guestEmail)
  const devSession = {
    user: {
      id: guestUserId,
      email: guestEmail,
      name: guestName,
      image: null,
      roles: ['guest'],
      groups: [],
      tenantId: null,
      metadata: {
        accountType: 'guest',
        managedBy: 'dev-auth',
      },
    },
    expires: new Date(Date.now() + 1000 * 60 * 60).toISOString(),
  }

  const csrfToken = 'dev-csrf-token'

  const jsonResponse = (payload: unknown, init: ResponseInit = {}) =>
    new Response(JSON.stringify(payload), {
      status: init.status ?? 200,
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'no-store',
        ...(init.headers || {}),
      },
    })

  const absUrl = (relative: string, base: URL): string => {
    try {
      return new URL(relative, base.origin).toString()
    } catch {
      return base.origin + '/'
    }
  }

  const handleGet = async (request: Request) => {
    const url = new URL(request.url)
    const pathname = url.pathname
    if (pathname.endsWith('/session')) {
      if (hasSignoutCookie(request)) return jsonResponse(null)
      return jsonResponse(devSession)
    }
    if (pathname.endsWith('/csrf')) {
      return jsonResponse({ csrfToken, cookie: csrfToken })
    }
    if (pathname.endsWith('/providers')) {
      const cb = absUrl(url.searchParams.get('callbackUrl') || '/', url)
      return jsonResponse({
        credentials: {
          id: 'credentials',
          name: 'AMI Credentials',
          type: 'credentials',
          signinUrl: '/auth/signin',
          callbackUrl: cb,
        },
        guest: {
          id: 'guest',
          name: 'Guest',
          type: 'credentials',
          signinUrl: '/api/auth/signin/guest',
          callbackUrl: cb,
        },
      })
    }
    if (pathname.includes('/signin')) {
      return jsonResponse({ url: absUrl(url.searchParams.get('callbackUrl') || '/', url) })
    }
    if (pathname.endsWith('/signout')) {
      return jsonResponse({ url: absUrl(url.searchParams.get('callbackUrl') || '/', url) })
    }
    return jsonResponse({ ok: true })
  }

  const handlePost = async (request: Request) => {
    const url = new URL(request.url)
    const pathname = url.pathname
    const resolveCallback = (params: URLSearchParams) =>
      absUrl(params.get('callbackUrl') || url.searchParams.get('callbackUrl') || '/', url)
    if (pathname.endsWith('/signout')) {
      const body = await request.clone().text().catch(() => '')
      const callbackUrl = resolveCallback(new URLSearchParams(body))
      return new Response(JSON.stringify({ url: callbackUrl }), {
        status: 200,
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          'Cache-Control': 'no-store',
          'Set-Cookie': DEV_SIGNOUT_SET,
        },
      })
    }
    if (pathname.includes('/signin') || pathname.includes('/callback')) {
      const body = await request.clone().text().catch(() => '')
      const callbackUrl = resolveCallback(new URLSearchParams(body))
      return new Response(JSON.stringify({ url: callbackUrl }), {
        status: 200,
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          'Cache-Control': 'no-store',
          'Set-Cookie': DEV_SIGNOUT_CLEAR,
        },
      })
    }
    return jsonResponse({ ok: true })
  }

  const devAuth = (...args: any[]) => {
    if (args.length === 0) {
      return isSignedOutFromHeaders().then((out) => (out ? null : devSession))
    }

    const [firstArg] = args

    if (typeof firstArg === 'function') {
      const handler = firstArg
      return async (...handlerArgs: any[]) => {
        const [req] = handlerArgs
        const signedOut = req && typeof req === 'object' ? hasSignoutCookie(req as Request) : false
        const session = signedOut ? null : devSession
        if (req && typeof req === 'object') {
          ;(req as any).auth = session
        }
        return handler(...handlerArgs)
      }
    }

    const req = firstArg
    if (req && typeof req === 'object') {
      const signedOut = hasSignoutCookie(req as Request)
      ;(req as any).auth = signedOut ? null : devSession
    }
    return Promise.resolve(devSession)
  }

  return {
    auth: devAuth,
    handlers: {
      GET: handleGet,
      POST: handlePost,
    },
    signIn: async () => ({ ok: true, url: '/' }),
    signOut: async () => ({ ok: true, url: '/' }),
  }
}

let authExportsPromise: Promise<AuthExports> | null = null

const HAS_NEXT_RUNTIME = typeof process.env.NEXT_RUNTIME === 'string' && process.env.NEXT_RUNTIME.length > 0
const FORCE_DEV_AUTH =
  process.env.AMI_AUTH_FORCE_DEV === '1' || (!HAS_NEXT_RUNTIME && process.env.NODE_ENV !== 'production')

async function initialiseAuthExports(): Promise<AuthExports> {
  if (FORCE_DEV_AUTH) {
    return createDevAuth()
  }
  try {
    const config = await loadAuthConfig()
    const require = createRequire(import.meta.url)
    const mod = require('next-auth')
    const factory = (mod as any).default ?? mod
    const potentialExports = typeof factory === 'function' ? factory(config) : factory

    if (
      potentialExports &&
      typeof potentialExports === 'object' &&
      typeof (potentialExports as any).auth === 'function' &&
      typeof (potentialExports as any).handlers === 'object'
    ) {
      return potentialExports as AuthExports
    }

    console.warn(
      '[ux/auth] next-auth module did not return expected exports, using dev auth implementation instead.',
    )
    return createDevAuth()
  } catch (err) {
    console.warn('[ux/auth] next-auth initialisation failed, using dev auth implementation.', err)
    return createDevAuth()
  }
}

function getAuthExports(): Promise<AuthExports> {
  if (!authExportsPromise) {
    authExportsPromise = initialiseAuthExports()
  }
  return authExportsPromise
}

export function auth(...args: any[]) {
  if (args.length && typeof args[0] === 'function') {
    const handler = args[0]
    return async (...innerArgs: any[]) => {
      const exports = await getAuthExports()
      const resolved = exports.auth(handler)
      const callable = typeof resolved === 'function' ? resolved : () => resolved
      return callable(...innerArgs)
    }
  }
  return getAuthExports().then(({ auth }) => auth(...args))
}

export const handlers = {
  GET: async (...args: any[]) => {
    const exports = await getAuthExports()
    return exports.handlers.GET(...args)
  },
  POST: async (...args: any[]) => {
    const exports = await getAuthExports()
    return exports.handlers.POST(...args)
  },
}

export function signIn(...args: any[]) {
  return getAuthExports().then(({ signIn }) => signIn(...args))
}

export function signOut(...args: any[]) {
  return getAuthExports().then(({ signOut }) => signOut(...args))
}

export const authGetHandler = async (...args: any[]) => handlers.GET(...args)
export const authPostHandler = async (...args: any[]) => handlers.POST(...args)
