const { expect } = require('chai')
const _ = require('lodash')

const SPCPAuthClient = require('../SPCPAuthClient.class')

describe('SPCPAuthClient - Constructor Tests', () => {
  it('should reject construction if parameters missing', () => {
    const config = {
      partnerEntityId: 'partnerEntityId',
      idpEndpoint: 'idpEndpoint',
      idpLoginURL: 'idpLoginURL',
      appSigningKey: 'appSigningKey',
      appEncryptionKey: 'appEncryptionKey',
      appCert: 'appCert',
      spcpCert: 'spcpCert',
      esrvcID: 'esrvcID',
    }
    // create a macro function that returns a
    // function that expect() can invoke
    const makeClientWithout = param =>
      () => new SPCPAuthClient(_.omit(config, param))

    expect(makeClientWithout('partnerEntityId')).to.throw(Error)
    expect(makeClientWithout('idpEndpoint')).to.throw(Error)
    expect(makeClientWithout('idpLoginURL')).to.throw(Error)
    expect(makeClientWithout('appSigningKey')).to.throw(Error)
    expect(makeClientWithout('appEncryptionKey')).to.throw(Error)
    expect(makeClientWithout('appCert')).to.throw(Error)
    expect(makeClientWithout('spcpCert')).to.throw(Error)
    expect(makeClientWithout('esrvcID')).to.throw(Error)
  })

  it('should correctly construct a client', () => {
    const config = {
      partnerEntityId: 'partnerEntityId',
      idpEndpoint: 'idpEndpoint',
      idpLoginURL: 'idpLoginURL',
      appSigningKey: 'appSigningKey',
      appEncryptionKey: 'appEncryptionKey',
      appCert: 'appCert',
      spcpCert: 'spcpCert',
      esrvcID: 'esrvcID',
    }
    const authClient = new SPCPAuthClient(config)
    expect(authClient.partnerEntityId).to.equal(config.partnerEntityId)
    expect(authClient.idpEndpoint).to.equal(config.idpEndpoint)
    expect(authClient.idpLoginURL).to.equal(config.idpLoginURL)
    expect(authClient.appSigningKey).to.equal(config.appSigningKey)
    expect(authClient.appEncryptionKey).to.equal(config.appEncryptionKey)
    expect(authClient.appCert).to.equal(config.appCert)
    expect(authClient.spcpCert).to.equal(config.spcpCert)
    expect(authClient.esrvcID).to.equal(config.esrvcID)
    expect(authClient.jwtAlgorithm).to.equal('RS256')
  })
})
