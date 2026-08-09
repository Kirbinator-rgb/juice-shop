/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { randomBytes } from 'crypto'

import config from 'config'
import { type Request, type Response, type NextFunction } from 'express'

import type { Memory as MemoryConfig } from '../lib/config.types'
import * as challengeUtils from '../lib/challengeUtils'
import { challenges, users } from '../data/datacache'
import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'

const RESET_TOKEN_TTL_MS = 15 * 60 * 1000

interface ResetGrant {
  hashedToken: string
  userId: number
  expiresAt: number
}

// Outstanding reset grants, keyed by email. Only the hash of a token is held, so a dump of
// this map does not let anyone complete a reset.
const resetGrants = new Map<string, ResetGrant>()

/**
 * Issues a single-use reset token for an email address, if that address has an account.
 * The token goes out of band to the address on file, so knowing the address is not enough
 * to complete a reset.
 */
async function requestReset (email: string) {
  const user = await UserModel.findOne({ where: { email } })
  if (!user) {
    return
  }
  const token = randomBytes(32).toString('hex')
  resetGrants.set(email, {
    hashedToken: security.hmac(token),
    userId: user.id,
    expiresAt: Date.now() + RESET_TOKEN_TTL_MS
  })
  // Stands in for the reset mail this deployment has no transport for. It must never travel
  // back in the HTTP response, or naming an address would again be enough to take an account.
  console.log(`Password reset link issued for ${email}: /#/reset-password?token=${token}`)
}

function consumeGrant (email: string, token: string) {
  const grant = resetGrants.get(email)
  if (!grant || grant.expiresAt < Date.now() || grant.hashedToken !== security.hmac(token)) {
    return undefined
  }
  resetGrants.delete(email) // single use, burned before the password is written
  return grant
}

export function resetPassword () {
  return async ({ body, connection }: Request, res: Response, next: NextFunction) => {
    const email = body.email
    const token = body.token
    const newPassword = body.new
    const repeatPassword = body.repeat
    if (!email) {
      next(new Error('Blocked illegal activity by ' + connection.remoteAddress))
      return
    }
    try {
      // A security question is public knowledge to anyone willing to research the account
      // holder, so it can no longer stand in for proof of address ownership (ASVS 6.3.3).
      // Without a token this is a request for one, and the reply is the same either way so
      // the endpoint cannot be used to discover which addresses are registered.
      if (!token) {
        await requestReset(email)
        res.status(202).json({ status: 'If that address has an account, a reset link has been sent to it.' })
        return
      }
      if (!newPassword || newPassword === 'undefined') {
        res.status(401).send(res.__('Password cannot be empty.'))
        return
      }
      if (newPassword !== repeatPassword) {
        res.status(401).send(res.__('New and repeated password do not match.'))
        return
      }
      const grant = consumeGrant(email, token)
      if (!grant) {
        res.status(401).send(res.__('Wrong answer to security question.'))
        return
      }
      const user = await UserModel.findByPk(grant.userId)
      if (user) {
        const updatedUser = await user.update({ password: newPassword })
        verifySecurityAnswerChallenges(updatedUser, body.answer ?? '')
        res.json({ user: updatedUser })
      }
    } catch (error) {
      next(error)
    }
  }
}

function verifySecurityAnswerChallenges (user: UserModel, answer: string) {
  challengeUtils.solveIf(challenges.resetPasswordJimChallenge, () => { return user.id === users.jim.id && answer === 'Samuel' })
  challengeUtils.solveIf(challenges.resetPasswordBenderChallenge, () => { return user.id === users.bender.id && answer === 'Stop\'n\'Drop' })
  challengeUtils.solveIf(challenges.resetPasswordBjoernChallenge, () => { return user.id === users.bjoern.id && answer === 'West-2082' })
  challengeUtils.solveIf(challenges.resetPasswordMortyChallenge, () => { return user.id === users.morty.id && answer === '5N0wb41L' })
  challengeUtils.solveIf(challenges.resetPasswordBjoernOwaspChallenge, () => { return user.id === users.bjoernOwasp.id && answer === 'Zaya' })
  challengeUtils.solveIf(challenges.resetPasswordUvoginChallenge, () => { return user.id === users.uvogin.id && answer === 'Silence of the Lambs' })
  challengeUtils.solveIf(challenges.geoStalkingMetaChallenge, () => {
    const securityAnswer = ((() => {
      const memories = config.get<MemoryConfig[]>('memories')
      for (let i = 0; i < memories.length; i++) {
        if (memories[i].geoStalkingMetaSecurityAnswer) {
          return memories[i].geoStalkingMetaSecurityAnswer
        }
      }
    })())
    return user.id === users.john.id && answer === securityAnswer
  })
  challengeUtils.solveIf(challenges.geoStalkingVisualChallenge, () => {
    const securityAnswer = ((() => {
      const memories = config.get<MemoryConfig[]>('memories')
      for (let i = 0; i < memories.length; i++) {
        if (memories[i].geoStalkingVisualSecurityAnswer) {
          return memories[i].geoStalkingVisualSecurityAnswer
        }
      }
    })())
    return user.id === users.emma.id && answer === securityAnswer
  })
}
