import 'next-auth'
import 'next-auth/jwt'

declare module 'next-auth' {
  interface Session {
    user: {
      id: string
      email: string
      name?: string | null
      image?: string | null
      roles: string[]
      groups: string[]
      tenantId?: string | null
      metadata?: Record<string, unknown>
    }
  }

  interface User {
    id: string
    email: string
    name?: string | null
    image?: string | null
    roles: string[]
    groups: string[]
    tenantId?: string | null
    metadata?: Record<string, unknown>
  }
}

declare module 'next-auth/jwt' {
  interface JWT {
    roles?: string[]
    groups?: string[]
    tenantId?: string | null
    metadata?: Record<string, unknown>
  }
}
