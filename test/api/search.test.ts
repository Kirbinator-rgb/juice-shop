/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import config from 'config'
import * as security from '../../lib/insecurity'
import type { Product as ProductConfig } from '../../lib/config.types'
import { createTestApp } from './helpers/setup'

const christmasProduct = config.get<ProductConfig[]>('products').filter(({ useForChristmasSpecialChallenge }) => useForChristmasSpecialChallenge)[0]
const pastebinLeakProduct = config.get<ProductConfig[]>('products').filter(({ keywordsForPastebinDataLeakChallenge }) => keywordsForPastebinDataLeakChallenge)[0]

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('/rest/products/search', () => {
  void it('GET product search with no matches returns no products', async () => {
    const res = await request(app)
      .get('/rest/products/search?q=nomatcheswhatsoever')
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.data.length, 0)
  })

  void it('GET product search with one match returns found product', async () => {
    const res = await request(app)
      .get('/rest/products/search?q=o-saft')
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.data.length, 1)
  })

  void it('GET product search does not leak a SQL error for a quote-terminated payload', async () => {
    const res = await request(app)
      .get("/rest/products/search?q=';")
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.data.length, 0)
  })

  void it('GET product search treats a UNION SELECT payload as literal search text', async () => {
    const res = await request(app)
      .get("/rest/products/search?q=' union select id,email,password from users--")
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.data.length, 0)
  })

  void it('GET product search treats a parenthesis-closing UNION SELECT payload as literal search text', async () => {
    const res = await request(app)
      .get("/rest/products/search?q=') union select id,email,password from users--")
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.data.length, 0)
  })

  void it('GET product search cannot UNION SELECT the Users table', async () => {
    const res = await request(app)
      .get("/rest/products/search?q=')) union select * from users--")
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.data.length, 0)
  })

  void it('GET product search cannot inject fixed columns via UNION SELECT', async () => {
    const res = await request(app)
      .get("/rest/products/search?q=')) union select '1','2','3','4','5','6','7','8','9' from users--")
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.data.length, 0)
  })

  void it('GET product search cannot exfiltrate user credentials via UNION SELECT', async () => {
    const res = await request(app)
      .get("/rest/products/search?q=')) union select id,'2','3',email,password,'6','7','8','9' from users--")
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.data.length, 0)

    const dataString = JSON.stringify(res.body.data)
    assert.ok(!dataString.includes(`admin@${config.get<string>('application.domain')}`), 'admin email must not leak')
    assert.ok(!dataString.includes(security.hash('admin123')), 'admin password hash must not leak')
  })

  void it('GET product search cannot exfiltrate the database schema via UNION SELECT', async () => {
    const res = await request(app)
      .get("/rest/products/search?q=')) union select sql,'2','3','4','5','6','7','8','9' from sqlite_master--")
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.data.length, 0)
    assert.ok(!JSON.stringify(res.body.data).includes('CREATE TABLE'), 'table definitions must not leak')
  })

  void it('GET product search cannot select logically deleted christmas special by default', async () => {
    const res = await request(app)
      .get('/rest/products/search?q=seasonal%20special%20offer')
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.data.length, 0)
  })

  void it('GET product search by description cannot select logically deleted christmas special due to forced early where-clause termination', async () => {
    const res = await request(app)
      .get("/rest/products/search?q=seasonal%20special%20offer'))--")
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.data.length, 0)
  })

  void it('GET product search cannot select logically deleted christmas special by commenting out the where clause', async () => {
    const res = await request(app)
      .get(`/rest/products/search?q=${christmasProduct.name}'))--`)
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.data.length, 0)
  })

  void it('GET product search cannot select logically deleted unsafe product by commenting out the where clause', async () => {
    const res = await request(app)
      .get(`/rest/products/search?q=${pastebinLeakProduct.name}'))--`)
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.data.length, 0)
  })

  void it('GET product search with empty search parameter returns all products', async () => {
    const productsRes = await request(app)
      .get('/api/Products')
    assert.equal(productsRes.status, 200)
    assert.ok(productsRes.headers['content-type']?.includes('application/json'))
    const products = productsRes.body.data

    const searchRes = await request(app)
      .get('/rest/products/search?q=')
    assert.equal(searchRes.status, 200)
    assert.ok(searchRes.headers['content-type']?.includes('application/json'))
    assert.equal(searchRes.body.data.length, products.length)
  })

  void it('GET product search without search parameter returns all products', async () => {
    const productsRes = await request(app)
      .get('/api/Products')
    assert.equal(productsRes.status, 200)
    assert.ok(productsRes.headers['content-type']?.includes('application/json'))
    const products = productsRes.body.data

    const searchRes = await request(app)
      .get('/rest/products/search')
    assert.equal(searchRes.status, 200)
    assert.ok(searchRes.headers['content-type']?.includes('application/json'))
    assert.equal(searchRes.body.data.length, products.length)
  })
})
