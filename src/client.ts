export type FetchLike = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>

export type AuthenticatedFetchOptions = RequestInit & {
  onUnauthorized?: () => void
}

export function createAuthenticatedFetch(fetchImpl: FetchLike = fetch): (input: RequestInfo | URL, init?: AuthenticatedFetchOptions) => Promise<Response> {
  return async (input, init = {}) => {
    const { onUnauthorized, headers, ...rest } = init
    const response = await fetchImpl(input, {
      credentials: 'include',
      ...rest,
      headers: {
        Accept: 'application/json',
        ...(headers || {}),
      },
    })
    if (response.status === 401 && typeof onUnauthorized === 'function') {
      onUnauthorized()
    }
    return response
  }
}

export const authenticatedFetch = createAuthenticatedFetch()
