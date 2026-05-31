import type { Link } from '@/types'
import { LINK_PASSWORD_QUERY_KEY, splitLinkPasswordTokenRef } from '#shared/utils/link-password'
import { parsePath, withQuery } from 'ufo'

const SOCIAL_BOTS = [
  'applebot',
  'discordbot',
  'facebot',
  'facebookexternalhit',
  'linkedinbot',
  'linkexpanding',
  'mastodon',
  'skypeuripreview',
  'slackbot',
  'slackbot-linkexpanding',
  'snapchat',
  'telegrambot',
  'tiktok',
  'twitterbot',
  'whatsapp',
]

const APPLE_DEVICE_UA_MARKERS = ['iphone', 'ipad', 'ipod', 'crios']

function isSocialBot(userAgent: string): boolean {
  const ua = userAgent.toLowerCase()
  return SOCIAL_BOTS.some(bot => ua.includes(bot))
}

function getDeviceRedirectUrl(userAgent: string, link: Link): string | null {
  if (!link.apple && !link.google)
    return null

  const ua = userAgent.toLowerCase()

  if (link.google && ua.includes('android')) {
    return link.google
  }

  if (link.apple && APPLE_DEVICE_UA_MARKERS.some(marker => ua.includes(marker))) {
    return link.apple
  }

  return null
}

function hasOgConfig(link: Link): boolean {
  return !!(link.title || link.image)
}

async function resolveQueryPasswordToken(token: string, storedPassword: string): Promise<{ password: string, ref?: string } | undefined> {
  const tokenRef = splitLinkPasswordTokenRef(token, storedPassword)
  if (!tokenRef.valid)
    return undefined

  if (await verifyLinkPassword(tokenRef.password, storedPassword))
    return tokenRef

  return undefined
}

export default eventHandler(async (event) => {
  const { pathname: slug } = parsePath(event.path.replace(/^\/|\/$/g, ''))
  const { slugRegex, reserveSlug } = useAppConfig()
  const { homeURL, linkCacheTtl, caseSensitive, redirectWithQuery, redirectStatusCode } = useRuntimeConfig(event)
  const { cloudflare } = event.context

  if (event.path === '/' && homeURL)
    return sendRedirect(event, homeURL)

  const { notFoundRedirect } = useRuntimeConfig(event)
  // Bypass redirect check for notFoundRedirect path to prevent infinite loop
  if (notFoundRedirect && event.path === notFoundRedirect) {
    return
  }

  if (slug && !reserveSlug.includes(slug) && slugRegex.test(slug) && cloudflare) {
    let link: Link | null = null

    const lowerCaseSlug = slug.toLowerCase()
    link = await getLink(event, caseSensitive ? slug : lowerCaseSlug, linkCacheTtl)

    if (!caseSensitive && !link && lowerCaseSlug !== slug) {
      console.log('original slug fallback:', `slug:${slug} lowerCaseSlug:${lowerCaseSlug}`)
      link = await getLink(event, slug, linkCacheTtl)
    }

    if (link) {
      let locale: RedirectLocale | undefined
      const getLocale = () => {
        locale ??= resolveRedirectLocale(event)
        return locale
      }
      const sendNoStoreHtml = (html: string) => {
        setHeader(event, 'Content-Type', 'text/html; charset=utf-8')
        setHeader(event, 'Cache-Control', 'no-store')
        return html
      }
      const userAgent = getHeader(event, 'user-agent') || ''
      const query = getQuery(event)

      // Extract access password from query param (browser-friendly alternative to header/form),
      // and strip it so it never leaks to the destination via redirectWithQuery.
      let queryPassword: string | undefined
      let queryPasswordRef: string | undefined
      if (link.password) {
        const rawToken = query[LINK_PASSWORD_QUERY_KEY]
        if (typeof rawToken === 'string' && rawToken.length > 0)
          queryPassword = rawToken
        delete query[LINK_PASSWORD_QUERY_KEY]
      }

      const shouldRedirectWithQuery = link.redirectWithQuery ?? redirectWithQuery
      const buildTarget = (url: string) => shouldRedirectWithQuery ? withQuery(url, query) : url

      let targetUrl = link.url
      const country = event.context.cloudflare?.request?.cf?.country
      if (country && typeof country === 'string' && link.geo?.[country.toUpperCase()]) {
        targetUrl = link.geo[country.toUpperCase()]!
      }
      targetUrl = buildTarget(targetUrl)

      const deviceRedirectUrl = getDeviceRedirectUrl(userAgent, link)
      const finalTargetUrl = deviceRedirectUrl ?? targetUrl

      // Password protection check
      if (link.password) {
        const headerPassword = getHeader(event, 'x-link-password')

        if (event.method === 'POST') {
          const body = await readBody(event)
          const submittedPassword = typeof body?.password === 'string' ? body.password : ''

          if (!await verifyLinkPassword(submittedPassword, link.password)) {
            return sendNoStoreHtml(generatePasswordHtml(slug, { hasError: true, locale: getLocale() }))
          }

          // Password correct - show unsafe warning if needed
          if (link.unsafe && body?.confirm !== 'true') {
            return sendNoStoreHtml(generateUnsafeWarningHtml(slug, finalTargetUrl, { password: submittedPassword, locale: getLocale() }))
          }
        }
        else if (headerPassword) {
          if (!await verifyLinkPassword(headerPassword, link.password)) {
            throw createError({ status: 403, statusText: 'Incorrect password' })
          }
          // Header-password path: check unsafe warning via x-link-confirm header
          if (link.unsafe && getHeader(event, 'x-link-confirm') !== 'true') {
            throw createError({ status: 403, statusText: 'Unsafe link: confirmation required (set x-link-confirm: true header)' })
          }
        }
        else if (queryPassword !== undefined) {
          const resolvedToken = await resolveQueryPasswordToken(queryPassword, link.password)
          if (!resolvedToken) {
            // Wrong token - fall back to the standard password form (no error), let the user type it.
            return sendNoStoreHtml(generatePasswordHtml(slug, { locale: getLocale() }))
          }
          queryPassword = resolvedToken.password
          queryPasswordRef = resolvedToken.ref
          // Token correct - show unsafe warning if needed (carry password forward for the confirm POST).
          if (link.unsafe) {
            return sendNoStoreHtml(generateUnsafeWarningHtml(slug, finalTargetUrl, { password: queryPassword, locale: getLocale() }))
          }
        }
        else {
          return sendNoStoreHtml(generatePasswordHtml(slug, { locale: getLocale() }))
        }
      }

      // Unsafe link warning (for links without password)
      if (!link.password && link.unsafe) {
        if (event.method === 'POST') {
          const body = await readBody(event)
          if (body?.confirm !== 'true') {
            return sendNoStoreHtml(generateUnsafeWarningHtml(slug, finalTargetUrl, { locale: getLocale() }))
          }
        }
        else {
          return sendNoStoreHtml(generateUnsafeWarningHtml(slug, finalTargetUrl, { locale: getLocale() }))
        }
      }

      event.context.link = link
      event.context.accessLogReferer = queryPasswordRef
      try {
        await useAccessLog(event)
      }
      catch (error) {
        console.error('Failed write access log:', error)
      }

      if (deviceRedirectUrl) {
        return sendRedirect(event, finalTargetUrl, +redirectStatusCode)
      }

      if (isSocialBot(userAgent) && hasOgConfig(link)) {
        const baseUrl = `${getRequestProtocol(event)}://${getRequestHost(event)}`
        const html = generateOgHtml(link, targetUrl, baseUrl)
        setHeader(event, 'Content-Type', 'text/html; charset=utf-8')
        return html
      }

      if (link.cloaking) {
        const baseUrl = `${getRequestProtocol(event)}://${getRequestHost(event)}`
        const html = generateCloakingHtml(link, targetUrl, baseUrl)
        setHeader(event, 'Content-Type', 'text/html; charset=utf-8')
        setHeader(event, 'Cache-Control', 'no-store, private')
        return html
      }

      return sendRedirect(event, finalTargetUrl, +redirectStatusCode)
    }
    else {
      if (notFoundRedirect) {
        return sendRedirect(event, notFoundRedirect, 302)
      }

      throw createError({ status: 404, statusText: 'Link not found' })
    }
  }
})
