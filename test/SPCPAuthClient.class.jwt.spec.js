const { expect } = require('chai')
const _ = require('lodash')
const fs = require('fs')
const jwt = require('jsonwebtoken')

const SPCPAuthClient = require('../SPCPAuthClient.class')

describe('SPCPAuthClient - JWT Tests', () => {
  const authClient = new SPCPAuthClient({
    partnerEntityId: 'partnerEntityId',
    idpEndpoint: 'idpEndpoint',
    idpLoginURL: 'idpLoginURL',
    appSigningKey: fs.readFileSync('./test/fixtures/certs/key.pem'),
    appEncryptionKey: fs.readFileSync('./test/fixtures/certs/key.pem'),
    appCert: fs.readFileSync('./test/fixtures/certs/server.crt'),
    spcpCert: 'spcpCert',
    esrvcID: 'esrvcID',
  })

  it('should create a verifiable token using jwt', () => {
    const payload = { key: 'value' }
    const token = authClient.createJWT(payload, '1 day')
    const result = jwt.verify(
      token, authClient.appCert, { algorithms: [ authClient.jwtAlgorithm ] }
    )
    expect(_.pick(result, 'key')).to.eql(payload)
  })

  it('should create a token it can verify', () => {
    const payload = { key: 'value' }
    const token = authClient.createJWT(payload, '1 day')
    const result = authClient.verifyJWT(token)
    expect(_.pick(result, 'key')).to.eql(payload)
  })

  it('should create a token it can verify and pass to callback', () => {
    const payload = { key: 'value' }
    const token = authClient.createJWT(payload, '1 day')
    const result = authClient.verifyJWT(token, (err, data) => {
      if (err) {
        throw err
      } else {
        expect(_.pick(data, 'key')).to.eql(payload)
      }
    })
    expect(result).to.equal(undefined)
  })
})
