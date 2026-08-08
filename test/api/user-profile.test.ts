/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import config from 'config'
import { createTestApp } from './helpers/setup'
import { login } from './helpers/auth'

let app: Express
let authHeader: { Cookie: string }

before(async () => {
  const result = await createTestApp()
  app = result.app
  const { token } = await login(app, { email: 'jim@juice-sh.op', password: 'ncc-1701' })
  authHeader = { Cookie: `token=${token}` }
}, { timeout: 60000 })

void describe('/profile', () => {
  void it('GET user profile is forbidden for unauthenticated user', async () => {
    const res = await request(app)
      .get('/profile')

    assert.equal(res.status, 500)
    assert.ok(res.headers['content-type']?.includes('text/html'))
    assert.ok(res.text.includes(`<h1>${config.get<string>('application.name')} (Express`))
    assert.ok(res.text.includes('Error: Blocked illegal activity'))
  })

  void it('GET user profile of authenticated user', async () => {
    const res = await request(app)
      .get('/profile')
      .set(authHeader)

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('text/html'))
    assert.ok(res.text.includes('id="email" type="email" name="email" value="jim@juice-sh.op"'))
  })

  void it('POST update username of authenticated user', async () => {
    const res = await request(app)
      .post('/profile')
      .set('Cookie', authHeader.Cookie)
      .field('username', 'Localhorst')
      .redirects(0)

    assert.equal(res.status, 302)
  })

  void it('GET Content-Security-Policy is static and not influenced by user data', async () => {
    const res = await request(app)
      .get('/profile')
      .set(authHeader)

    assert.equal(res.status, 200)
    const csp = res.headers['content-security-policy']
    assert.equal(csp, "img-src 'self'; script-src 'self'")
    assert.ok(!csp.includes('unsafe-inline'), 'CSP must not allow inline scripts')
    assert.ok(!csp.includes('unsafe-eval'), 'CSP must not allow eval')
  })

  void it('POST username containing a template expression is not evaluated', async () => {
    const update = await request(app)
      .post('/profile')
      .set('Cookie', authHeader.Cookie)
      .field('username', '#{7*7}')
      .redirects(0)
    assert.equal(update.status, 302)

    const res = await request(app)
      .get('/profile')
      .set(authHeader)
    assert.equal(res.status, 200)
    // 49 would mean the expression was evaluated server-side
    assert.ok(!res.text.includes('49'), 'template expression must not be evaluated')
  })
})
