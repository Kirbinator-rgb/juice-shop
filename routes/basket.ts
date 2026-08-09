/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { ProductModel } from '../models/product'
import { BasketModel } from '../models/basket'

import * as utils from '../lib/utils'
import * as security from '../lib/insecurity'

export function retrieveBasket () {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const id = parseInt(req.params.id, 10)
      // A basket may only ever be read by the user it belongs to. The id in the URL was
      // previously trusted as-is, so any authenticated customer could enumerate and read
      // every other customer's basket (OWASP A01, broken object level authorization).
      const user = security.authenticatedUsers.from(req)
      if (!user?.bid || isNaN(id) || user.bid !== id) {
        res.status(401).json({ error: 'Malicious activity detected' })
        return
      }
      const basket = await BasketModel.findOne({ where: { id }, include: [{ model: ProductModel, paranoid: false, as: 'Products' }] })
      if (((basket?.Products) != null) && basket.Products.length > 0) {
        for (let i = 0; i < basket.Products.length; i++) {
          basket.Products[i].name = req.__(basket.Products[i].name)
        }
      }

      res.json(utils.queryResultToJson(basket))
    } catch (error) {
      next(error)
    }
  }
}
