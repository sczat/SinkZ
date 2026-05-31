import { describe, expect, it } from 'vitest'
import { getAccessLogReferer } from '../../server/utils/access-log'
import { createLinkPasswordTokenWithRef, splitLinkPasswordTokenRef } from '../../shared/utils/link-password'
import { fetch, fetchWithAuth } from '../utils'

function createRefererEvent(path: string, referer?: string) {
  return {
    path,
    node: {
      req: {
        headers: referer ? { referer } : {},
        url: path,
      },
    },
  }
}

describe('access log referer', () => {
  it('creates and splits password tokens with embedded ref', () => {
    const token = createLinkPasswordTokenWithRef('Bv3gJYLr', 'S23ad', 'stored-password-hash')

    expect(token).toMatch(/^Bv3gJYLr_S23ad[\w-]{2}$/)
    expect(splitLinkPasswordTokenRef(token, 'stored-password-hash')).toEqual({ password: 'Bv3gJYLr', ref: 'S23ad', valid: true })
  })

  it('marks password tokens with modified embedded ref as invalid', () => {
    const token = createLinkPasswordTokenWithRef('Bv3gJYLr', 'S23ad', 'stored-password-hash')
    const modifiedToken = token.replace('S23ad', 'T45bc')

    expect(splitLinkPasswordTokenRef(modifiedToken, 'stored-password-hash')).toEqual({ password: 'Bv3gJYLr', valid: false })
  })

  it('marks password tokens with a different checksum secret as invalid', () => {
    const token = createLinkPasswordTokenWithRef('Bv3gJYLr', 'S23ad', 'stored-password-hash')

    expect(splitLinkPasswordTokenRef(token, 'other-stored-password-hash')).toEqual({ password: 'Bv3gJYLr', valid: false })
  })

  it('keeps regular password tokens valid without ref', () => {
    expect(splitLinkPasswordTokenRef('Bv3gJYLr')).toEqual({ password: 'Bv3gJYLr', valid: true })
  })

  it('prefers ref query over HTTP referer', () => {
    const event = createRefererEvent('/portfolio?ref=test', 'https://example.com/page')

    expect(getAccessLogReferer(event as never)).toBe('test')
  })

  it('uses verified token ref context when ref query is missing', () => {
    const event = createRefererEvent(`/portfolio?token=${createLinkPasswordTokenWithRef('Bv3gJYLr', 'S23ad', 'stored-password-hash')}`, 'https://example.com/page')
    event.context = { accessLogReferer: 'S23ad' }

    expect(getAccessLogReferer(event as never)).toBe('S23ad')
  })

  it('normalizes URL-style ref query to its host', () => {
    const event = createRefererEvent('/portfolio?ref=https%3A%2F%2Fcampaign.example.com%2Flanding%3Futm_source%3Dx')

    expect(getAccessLogReferer(event as never)).toBe('campaign.example.com')
  })

  it('falls back to HTTP referer when ref query is empty', () => {
    const event = createRefererEvent('/portfolio?ref=', 'https://example.com/page')

    expect(getAccessLogReferer(event as never)).toBe('example.com')
  })
})

describe('/api/stats/counters', () => {
  it('returns counters data with valid auth', async () => {
    const response = await fetchWithAuth('/api/stats/counters?slug=0')

    expect(response.status).toBe(200)

    const data = await response.json()
    expect(data).toHaveProperty('data')
  })

  it('returns counters with time filter', async () => {
    const now = Math.floor(Date.now() / 1000)
    const response = await fetchWithAuth(`/api/stats/counters?slug=1&startAt=${now - 86400}&endAt=${now}`)

    expect(response.status).toBe(200)

    const data = await response.json()
    expect(data).toHaveProperty('data')
  })

  it('returns data without slug filter', async () => {
    const response = await fetchWithAuth('/api/stats/counters')

    expect(response.status).toBe(200)

    const data = await response.json()
    expect(data).toHaveProperty('data')
  })

  it('returns 401 when accessing without auth', async () => {
    const response = await fetch('/api/stats/counters?slug=0')

    expect(response.status).toBe(401)
  })
})

describe('/api/stats/metrics', () => {
  it('returns metrics data with valid auth and type', async () => {
    const response = await fetchWithAuth('/api/stats/metrics?slug=0&type=browser')

    expect(response.status).toBe(200)

    const data = await response.json()
    expect(data).toHaveProperty('data')
  })

  it('returns metrics for different types', async () => {
    const types = ['browser', 'os', 'device', 'country', 'referer']

    for (const type of types) {
      const response = await fetchWithAuth(`/api/stats/metrics?slug=1&type=${type}`)
      expect(response.status).toBe(200)
    }
  })

  it('returns 400 for invalid metric type', async () => {
    const response = await fetchWithAuth('/api/stats/metrics?slug=0&type=invalid')

    expect(response.status).toBe(400)
  })

  it('returns 400 when type parameter is missing', async () => {
    const response = await fetchWithAuth('/api/stats/metrics?slug=0')

    expect(response.status).toBe(400)
  })

  it('returns 401 when accessing without auth', async () => {
    const response = await fetch('/api/stats/metrics?slug=0&type=browser')

    expect(response.status).toBe(401)
  })
})

describe('/api/stats/views', () => {
  it('returns views data with valid auth and unit', async () => {
    const response = await fetchWithAuth('/api/stats/views?slug=0&unit=day')

    expect(response.status).toBe(200)

    const data = await response.json()
    expect(data).toHaveProperty('data')
  })

  it('returns views for different units', async () => {
    const units = ['minute', 'hour', 'day']

    for (const unit of units) {
      const response = await fetchWithAuth(`/api/stats/views?slug=1&unit=${unit}`)
      expect(response.status).toBe(200)
    }
  })

  it('supports clientTimezone parameter', async () => {
    const response = await fetchWithAuth('/api/stats/views?slug=0&unit=day&clientTimezone=Asia/Shanghai')

    expect(response.status).toBe(200)
  })

  it('supports offset-style clientTimezone values', async () => {
    const response = await fetchWithAuth('/api/stats/views?slug=0&unit=day&clientTimezone=Etc/GMT-8')

    expect(response.status).toBe(200)
  })

  it('returns 400 for invalid clientTimezone format', async () => {
    const response = await fetchWithAuth('/api/stats/views?slug=0&unit=day&clientTimezone=invalid<>timezone')

    expect(response.status).toBe(400)
  })

  it('returns 400 for invalid unit', async () => {
    const response = await fetchWithAuth('/api/stats/views?slug=0&unit=invalid')

    expect(response.status).toBe(400)
  })

  it('returns 400 when unit parameter is missing', async () => {
    const response = await fetchWithAuth('/api/stats/views?slug=0')

    expect(response.status).toBe(400)
  })

  it('returns 401 when accessing without auth', async () => {
    const response = await fetch('/api/stats/views?slug=0&unit=day')

    expect(response.status).toBe(401)
  })
})

describe('/api/stats/heatmap', () => {
  it('supports clientTimezone parameter', async () => {
    const response = await fetchWithAuth('/api/stats/heatmap?clientTimezone=Asia/Shanghai')

    expect(response.status).toBe(200)
  })

  it('supports offset-style clientTimezone values', async () => {
    const response = await fetchWithAuth('/api/stats/heatmap?clientTimezone=Etc/GMT-8')

    expect(response.status).toBe(200)
  })

  it('returns 400 for invalid clientTimezone format', async () => {
    const response = await fetchWithAuth('/api/stats/heatmap?clientTimezone=invalid<>timezone')

    expect(response.status).toBe(400)
  })

  it('returns 401 when accessing without auth', async () => {
    const response = await fetch('/api/stats/heatmap?clientTimezone=Asia/Shanghai')

    expect(response.status).toBe(401)
  })
})

describe('/api/stats/export', () => {
  it('returns CSV with valid auth', async () => {
    const response = await fetchWithAuth('/api/stats/export')

    expect(response.status).toBe(200)
    expect(response.headers.get('content-type')).toContain('text/csv')

    const csv = await response.text()
    expect(csv.replace(/^\uFEFF/, '').split('\n')[0]).toBe('slug,url,viewer,views,referer')
  })

  it('supports time filter', async () => {
    const now = Math.floor(Date.now() / 1000)
    const response = await fetchWithAuth(`/api/stats/export?startAt=${now - 86400}&endAt=${now}`)

    expect(response.status).toBe(200)
  })

  it('supports slug filter', async () => {
    const response = await fetchWithAuth('/api/stats/export?slug=0')

    expect(response.status).toBe(200)
  })

  it('returns 400 for invalid time range', async () => {
    const now = Math.floor(Date.now() / 1000)
    const response = await fetchWithAuth(`/api/stats/export?startAt=${now}&endAt=${now - 86400}`)

    expect(response.status).toBe(400)
  })

  it('returns 401 when accessing without auth', async () => {
    const response = await fetch('/api/stats/export')

    expect(response.status).toBe(401)
  })
})
