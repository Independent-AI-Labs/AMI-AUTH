/**
 * Security Event Logger
 *
 * Provides structured logging for security-critical authentication events.
 * These logs are essential for security auditing and incident response.
 *
 * IMPORTANT: All security events should be logged before throwing errors
 * to ensure proper audit trails even if errors are caught upstream.
 */

export type SecurityEventType =
  | 'auth_service_failure'
  | 'guest_resolution_failure'
  | 'user_lookup_failure'
  | 'metadata_validation_failure'
  | 'credential_verification_failure'
  | 'session_creation_failure'

export interface SecurityEventContext {
  eventType: SecurityEventType
  message: string
  timestamp: string
  error?: Error | unknown
  details?: Record<string, unknown>
}

/**
 * Logs a security event with structured data
 *
 * This function uses console.error to ensure visibility in production logs.
 * The structured format makes it easy to parse and analyze security events.
 *
 * @param eventType - Type of security event (used for filtering/analysis)
 * @param message - Human-readable description of the event
 * @param error - Optional error object for additional context
 * @param details - Optional additional context data (sanitized before logging)
 */
export function logSecurityEvent(
  eventType: SecurityEventType,
  message: string,
  error?: Error | unknown,
  details?: Record<string, unknown>,
): void {
  const event: SecurityEventContext = {
    eventType,
    message,
    timestamp: new Date().toISOString(),
    error: error instanceof Error ? {
      name: error.name,
      message: error.message,
      stack: error.stack,
    } : error,
    details: sanitizeDetails(details),
  }

  console.error('[SECURITY EVENT]', JSON.stringify(event, null, 2))
}

/**
 * Sanitizes context details to prevent logging sensitive information
 *
 * Removes or masks fields that might contain passwords, tokens, or other
 * sensitive data before logging.
 */
function sanitizeDetails(details?: Record<string, unknown>): Record<string, unknown> | undefined {
  if (!details) return undefined

  const sanitized: Record<string, unknown> = {}
  const sensitiveKeys = ['password', 'token', 'secret', 'apiKey', 'api_key', 'clientSecret', 'client_secret']

  for (const [key, value] of Object.entries(details)) {
    const lowerKey = key.toLowerCase()
    if (sensitiveKeys.some(sensitive => lowerKey.includes(sensitive))) {
      sanitized[key] = '[REDACTED]'
    } else {
      sanitized[key] = value
    }
  }

  return sanitized
}
