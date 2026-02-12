import type { NextFetchEvent, NextRequest } from 'next/server'
import { NextResponse } from 'next/server'

import { auth } from './server'

const PUBLIC_FILE = /\.[^/]+$/
const DEFAULT_PUBLIC_PREFIXES = ['/_next', '/auth', '/api/auth', '/favicon.ico', '/docs', '/static']

type AuthenticatedRequest = NextRequest & {
  auth?: {
    user?: {
      id: string
      email: string
      roles?: string[]
      tenantId?: string | null
    }
  }
}

export type AuthMiddlewareOptions = {
  publicRoutes?: (RegExp | string)[]
  signInPath?: string
  headerForwarding?: boolean
}

function isPublicRoute(url: URL, custom: (RegExp | string)[] = []): boolean {
  const pathname = url.pathname
  if (PUBLIC_FILE.test(pathname)) return true
  const candidates = [...DEFAULT_PUBLIC_PREFIXES, ...custom]
  return candidates.some((candidate) => {
    if (typeof candidate === 'string') {
      return pathname.startsWith(candidate)
    }
    return candidate.test(pathname)
  })
}

export function createAuthMiddleware(options: AuthMiddlewareOptions = {}) {
  const { publicRoutes = [], signInPath = '/auth/signin', headerForwarding = true } = options

  const handlerOrPromise = auth((req: AuthenticatedRequest, event: NextFetchEvent) => {
    // Redirect HTTP to HTTPS
    const protocol = req.headers.get('x-forwarded-proto') || req.nextUrl.protocol
    if (protocol === 'http:') {
      const httpsUrl = new URL(req.nextUrl.href)
      httpsUrl.protocol = 'https:'
      return NextResponse.redirect(httpsUrl, 301)
    }

    if (isPublicRoute(req.nextUrl, publicRoutes)) {
      return NextResponse.next()
    }

    if (!req.auth?.user) {
      const redirectUrl = new URL(signInPath, req.nextUrl.origin)
      redirectUrl.searchParams.set('callbackUrl', req.nextUrl.pathname + req.nextUrl.search)
      return NextResponse.redirect(redirectUrl)
    }

    const response = NextResponse.next()
    if (headerForwarding && req.auth?.user) {
      response.headers.set('x-ami-user-id', req.auth.user.id)
      response.headers.set('x-ami-user-email', req.auth.user.email)
      response.headers.set('x-ami-user-roles', req.auth.user.roles?.join(',') ?? '')
      if (req.auth.user.tenantId) response.headers.set('x-ami-tenant-id', req.auth.user.tenantId)
    }

    return response
  })

  if (typeof handlerOrPromise === 'function') return handlerOrPromise
  return async (req: AuthenticatedRequest, event: NextFetchEvent) => {
    const resolved = await handlerOrPromise
    return resolved(req, event)
  }
}

export const AUTH_MIDDLEWARE_MATCHER = [
  '/((?!_next/static|_next/image|api/auth|auth|favicon.ico|docs).*)',
]

export default createAuthMiddleware
