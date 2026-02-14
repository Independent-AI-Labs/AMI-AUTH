/**
 * Authentication Error Classes
 *
 * These error classes are used to distinguish between different types of
 * authentication failures and ensure proper error handling throughout the
 * auth module. All authentication errors should be logged before being thrown.
 */

/**
 * Base class for all authentication-related errors
 */
export class AuthError extends Error {
  constructor(message: string, public readonly context?: Record<string, unknown>) {
    super(message)
    this.name = 'AuthError'
    Error.captureStackTrace(this, this.constructor)
  }
}

/**
 * Thrown when the authentication service is unavailable or returns an error
 *
 * SECURITY CRITICAL: This error indicates that authentication cannot be performed
 * reliably. Do NOT fall back to guest accounts or local templates when this occurs.
 */
export class AuthenticationServiceError extends AuthError {
  constructor(message: string, context?: Record<string, unknown>) {
    super(message, context)
    this.name = 'AuthenticationServiceError'
  }
}

/**
 * Thrown when a user lookup fails (user not found in any store)
 *
 * This is distinct from AuthenticationServiceError because it indicates the
 * authentication service is working, but the specific user does not exist.
 */
export class UserNotFoundError extends AuthError {
  constructor(email: string, context?: Record<string, unknown>) {
    super(`User not found: ${email}`, { ...context, email })
    this.name = 'UserNotFoundError'
  }
}

/**
 * Thrown when required metadata validation fails
 *
 * This occurs when a required metadata field is missing or invalid. This helps
 * prevent incomplete user records from being processed.
 */
export class MetadataValidationError extends AuthError {
  constructor(fieldName: string, reason: string, context?: Record<string, unknown>) {
    super(`Metadata validation failed for field '${fieldName}': ${reason}`, { ...context, fieldName, reason })
    this.name = 'MetadataValidationError'
  }
}
