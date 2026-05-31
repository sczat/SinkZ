export const LINK_PASSWORD_HASH_PREFIX = 'sink-pwd:v1:'
export const LINK_PASSWORD_MASK_PREFIX = '__SINK_MASKED__'
// Query param used to pass a link's access password directly in the URL (e.g. /slug?token=secret)
export const LINK_PASSWORD_QUERY_KEY = 'token'

interface LinkPasswordTokenRef {
  password: string
  ref?: string
  valid: boolean
}

interface LinkPasswordTokenPayload {
  v: 1
  slug: string
  password: string
  ref?: string
}

const LINK_PASSWORD_TOKEN_VERSION = 1
const LINK_PASSWORD_TOKEN_IV_BYTES = 12

export function isMaskedLinkPassword(password: string): boolean {
  return password.startsWith(LINK_PASSWORD_MASK_PREFIX)
}

export function isHashedLinkPassword(password: string): boolean {
  return password.startsWith(LINK_PASSWORD_HASH_PREFIX)
}

export async function createLinkPasswordTokenWithRef(password: string, ref: string | undefined, slug: string, secret: string): Promise<string> {
  const normalizedRef = ref?.trim()
  const payload: LinkPasswordTokenPayload = {
    v: LINK_PASSWORD_TOKEN_VERSION,
    slug,
    password,
    ...(normalizedRef ? { ref: normalizedRef } : {}),
  }
  const iv = crypto.getRandomValues(new Uint8Array(LINK_PASSWORD_TOKEN_IV_BYTES))
  const key = await getLinkPasswordTokenKey(secret)
  const encrypted = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    toArrayBuffer(encodeText(JSON.stringify(payload))),
  ))
  const token = new Uint8Array(iv.length + encrypted.length)
  token.set(iv)
  token.set(encrypted, iv.length)

  return bytesToBase64Url(token)
}

export async function decryptLinkPasswordToken(token: string, secret: string): Promise<LinkPasswordTokenRef & { slug?: string }> {
  if (!secret)
    return { password: token, valid: false }

  try {
    const bytes = base64UrlToBytes(token)
    if (bytes.length <= LINK_PASSWORD_TOKEN_IV_BYTES)
      return { password: token, valid: false }

    const iv = bytes.slice(0, LINK_PASSWORD_TOKEN_IV_BYTES)
    const encrypted = bytes.slice(LINK_PASSWORD_TOKEN_IV_BYTES)
    const key = await getLinkPasswordTokenKey(secret)
    const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, toArrayBuffer(encrypted))
    const payload = JSON.parse(decodeText(new Uint8Array(decrypted))) as unknown

    if (!isLinkPasswordTokenPayload(payload))
      return { password: token, valid: false }

    return {
      password: payload.password,
      ref: payload.ref,
      slug: payload.slug,
      valid: true,
    }
  }
  catch {
    return { password: token, valid: false }
  }
}

async function getLinkPasswordTokenKey(secret: string): Promise<CryptoKey> {
  const keyBytes = await crypto.subtle.digest('SHA-256', toArrayBuffer(encodeText(secret)))
  return await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['encrypt', 'decrypt'])
}

function isLinkPasswordTokenPayload(value: unknown): value is LinkPasswordTokenPayload {
  if (!value || typeof value !== 'object')
    return false

  const payload = value as Record<string, unknown>
  return payload.v === LINK_PASSWORD_TOKEN_VERSION
    && typeof payload.slug === 'string'
    && payload.slug.length > 0
    && typeof payload.password === 'string'
    && payload.password.length > 0
    && (payload.ref === undefined || typeof payload.ref === 'string')
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

function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = ''
  for (const byte of bytes) {
    binary += String.fromCharCode(byte)
  }
  return btoa(binary)
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replaceAll('=', '')
}

function base64UrlToBytes(value: string): Uint8Array {
  const base64 = value.replaceAll('-', '+').replaceAll('_', '/')
  const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, '=')
  return Uint8Array.from(atob(padded), char => char.charCodeAt(0))
}

function encodeText(value: string): Uint8Array {
  return new TextEncoder().encode(value)
}

function decodeText(value: Uint8Array): string {
  return new TextDecoder().decode(value)
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer
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
