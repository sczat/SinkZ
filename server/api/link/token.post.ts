import { createLinkPasswordTokenWithRef } from '#shared/utils/link-password'
import { z } from 'zod'

const LinkTokenSchema = z.object({
  slug: z.string().trim().min(1).max(2048),
  password: z.string().trim().min(1).max(128),
  ref: z.string().trim().min(1).max(256).optional(),
})

defineRouteMeta({
  openAPI: {
    description: 'Generate an encrypted access token for a password-protected short link',
    security: [{ bearerAuth: [] }],
    requestBody: {
      required: true,
      content: {
        'application/json': {
          schema: {
            type: 'object',
            required: ['slug', 'password'],
            properties: {
              slug: { type: 'string', description: 'The short link slug' },
              password: { type: 'string', description: 'The link access password' },
              ref: { type: 'string', description: 'Optional encrypted referer label' },
            },
          },
        },
      },
    },
  },
})

export default eventHandler(async (event) => {
  const { slug, password, ref } = await readValidatedBody(event, LinkTokenSchema.parse)
  const { caseSensitive, linkTokenSecret } = useRuntimeConfig(event)
  if (!linkTokenSecret) {
    throw createError({ status: 500, statusText: 'Link token secret is not configured' })
  }

  const normalizedSlug = normalizeSlug(event, slug)
  const link = await getLink(event, caseSensitive ? slug : normalizedSlug)
  if (!link) {
    throw createError({ status: 404, statusText: 'Link not found' })
  }

  if (!link.password) {
    throw createError({ status: 400, statusText: 'Link is not password protected' })
  }

  if (!await verifyLinkPassword(password, link.password)) {
    throw createError({ status: 403, statusText: 'Incorrect password' })
  }

  const token = await createLinkPasswordTokenWithRef(password, ref, link.slug, linkTokenSecret)
  return {
    token,
    shortLink: `${buildShortLink(event, link.slug)}?token=${encodeURIComponent(token)}`,
  }
})
