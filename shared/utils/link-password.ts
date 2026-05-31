export const LINK_PASSWORD_HASH_PREFIX = 'sink-pwd:v1:'
export const LINK_PASSWORD_MASK_PREFIX = '__SINK_MASKED__'
// Query param used to pass a link's access password directly in the URL (e.g. /slug?token=secret)
export const LINK_PASSWORD_QUERY_KEY = 'token'

interface LinkPasswordTokenRef {
  password: string
  ref?: string
  valid: boolean
}

const LINK_PASSWORD_TOKEN_REF_SEPARATOR = '_'
const LINK_PASSWORD_TOKEN_REF_CHECKSUM_LENGTH = 2
const LINK_PASSWORD_TOKEN_REF_CHECKSUM_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'

export function isMaskedLinkPassword(password: string): boolean {
  return password.startsWith(LINK_PASSWORD_MASK_PREFIX)
}

export function isHashedLinkPassword(password: string): boolean {
  return password.startsWith(LINK_PASSWORD_HASH_PREFIX)
}

export function createLinkPasswordTokenWithRef(password: string, ref: string | undefined, checksumSecret: string): string {
  const normalizedRef = ref?.trim()
  if (!normalizedRef)
    return password

  return `${password}${LINK_PASSWORD_TOKEN_REF_SEPARATOR}${normalizedRef}${createLinkPasswordTokenRefChecksum(password, normalizedRef, checksumSecret)}`
}

export function splitLinkPasswordTokenRef(token: string, checksumSecret?: string): LinkPasswordTokenRef {
  const separatorIndex = token.indexOf(LINK_PASSWORD_TOKEN_REF_SEPARATOR)
  if (separatorIndex <= 0)
    return { password: token, valid: true }

  const password = token.slice(0, separatorIndex)
  const refWithChecksum = token.slice(separatorIndex + 1)
  if (refWithChecksum.length <= LINK_PASSWORD_TOKEN_REF_CHECKSUM_LENGTH)
    return { password, valid: false }

  const ref = refWithChecksum.slice(0, -LINK_PASSWORD_TOKEN_REF_CHECKSUM_LENGTH)
  const checksum = refWithChecksum.slice(-LINK_PASSWORD_TOKEN_REF_CHECKSUM_LENGTH)
  if (!checksumSecret || checksum !== createLinkPasswordTokenRefChecksum(password, ref, checksumSecret))
    return { password, valid: false }

  return {
    password,
    ref,
    valid: true,
  }
}

function createLinkPasswordTokenRefChecksum(password: string, ref: string, checksumSecret: string): string {
  let hash = 2166136261
  const value = `${password}\0${ref}\0${checksumSecret}`

  for (const char of value) {
    hash ^= char.codePointAt(0) ?? 0
    hash = Math.imul(hash, 16777619)
  }

  return [
    LINK_PASSWORD_TOKEN_REF_CHECKSUM_ALPHABET.charAt(hash & 0x3F),
    LINK_PASSWORD_TOKEN_REF_CHECKSUM_ALPHABET.charAt((hash >>> 6) & 0x3F),
  ].join('')
}

function decodeBase64Url(value: string): string | undefined {
  try {
    const base64 = value.replaceAll('-', '+').replaceAll('_', '/')
    const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, '=')
    const bytes = Uint8Array.from(atob(padded), char => char.charCodeAt(0))
    return new TextDecoder().decode(bytes)
  }
  catch {
    return undefined
  }
}

export function getLinkPasswordTail(password: string): string {
  if (!isHashedLinkPassword(password))
    return [...password].slice(-3).join('')

  const parts = password.slice(LINK_PASSWORD_HASH_PREFIX.length).split(':')
  const tail = parts[3]
  return tail ? decodeBase64Url(tail) ?? '' : ''
}

export function maskLinkPassword(password: string): string {
  return `${LINK_PASSWORD_MASK_PREFIX}•••${getLinkPasswordTail(password)}`
}
