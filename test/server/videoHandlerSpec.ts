/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import { neutralizeScriptClosings } from '../../routes/videoHandler'

const expect = chai.expect

describe('videoHandler', () => {
  describe('neutralizeScriptClosings', () => {
    it('strips a closing script tag used to break out of the subtitle block', () => {
      const payload = 'WEBVTT\n\n</script><script>alert(`xss`)</script>'

      const result = neutralizeScriptClosings(payload)

      expect(result).to.not.contain('</script')
      expect(result).to.not.contain('</script><script>')
    })

    it('strips closing script tags regardless of case or trailing characters', () => {
      expect(neutralizeScriptClosings('a</SCRIPT>b')).to.not.contain('</SCRIPT')
      expect(neutralizeScriptClosings('a</script >b')).to.not.contain('</script')
      expect(neutralizeScriptClosings('a</script/b')).to.not.contain('</script')
    })

    it('leaves legitimate WebVTT content untouched', () => {
      const subtitles = 'WEBVTT\n\n00:00:01.000 --> 00:00:04.000\nHello <i>world</i>, 1 < 2 & 3 > 2\n'

      expect(neutralizeScriptClosings(subtitles)).to.equal(subtitles)
    })
  })
})
