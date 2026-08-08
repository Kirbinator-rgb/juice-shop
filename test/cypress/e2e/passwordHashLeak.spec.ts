describe('challenge "Password Hash Leak"', () => {
  beforeEach(() => {
    cy.login({ email: 'admin@juice-sh.op', password: 'admin123' })
  })

  it('should not leak the password hash via the fields parameter', () => {
    cy.request({
      method: 'GET',
      url: '/rest/user/whoami?fields=id,email,password'
    }).then((res) => {
      expect(res.body.user).to.not.have.property('password')
      expect(res.body.user.email).to.equal('admin@juice-sh.op')
    })
  })

  it('should not leak any other non-allow-listed field via the fields parameter', () => {
    cy.request({
      method: 'GET',
      url: '/rest/user/whoami?fields=totpSecret,role,password,deletedAt'
    }).then((res) => {
      expect(res.body.user).to.deep.equal({})
    })
  })

  it('should still return allow-listed fields via the fields parameter', () => {
    cy.request({
      method: 'GET',
      url: '/rest/user/whoami?fields=id,email'
    }).then((res) => {
      expect(res.body.user.id).to.be.a('number')
      expect(res.body.user.email).to.equal('admin@juice-sh.op')
      expect(res.body.user).to.not.have.property('password')
    })
  })
})
