/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('/rest/track-order/:id', () => {
  void it('GET tracking results for the order id', async () => {
    const res = await request(app)
      .get('/rest/track-order/5267-f9cd5882f54c75a3')
    assert.equal(res.status, 200)
  })

  void it('GET cannot exfiltrate all orders by injecting into orderId', async () => {
    const res = await request(app)
      .get('/rest/track-order/%27%20%7C%7C%20true%20%7C%7C%20%27')
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.ok(Array.isArray(res.body.data))
    // The injection matches nothing, so only the echoed placeholder comes back and no
    // order data (email, totalPrice, products) is disclosed.
    assert.equal(res.body.data.length, 1)
    assert.equal(res.body.data[0].email, undefined)
    assert.equal(res.body.data[0].totalPrice, undefined)
    assert.equal(res.body.data[0].products, undefined)
  })

  void it('GET reflects no markup back from the order id', async () => {
    const res = await request(app)
      .get('/rest/track-order/' + encodeURIComponent('<iframe src="javascript:alert(`xss`)">'))
    assert.equal(res.status, 200)
    assert.ok(!res.text.includes('<iframe'), 'markup must not be reflected')
    assert.ok(!res.text.includes('javascript:'), 'javascript: URL must not be reflected')
  })
})
