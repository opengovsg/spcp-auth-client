const { expect } = require('chai')
const SPCPAuthClient = require('../build/SPCPAuthClient')

describe('SPCPAuthClient - createRedirectURL', () => {
  const authClient = new SPCPAuthClient({
    partnerEntityId: 'partnerEntityId',
    idpEndpoint: 'idpEndpoint',
    idpLoginURL: 'idpLoginURL',
    appKey: 'appKey',
    appEncryptionKey: 'appEncryptionKey',
    appCert: 'appCert',
    spcpCert: 'spcpCert',
    esrvcID: 'esrvcID',
  })
  it('should return Error on no target', () => {
    expect(authClient.createRedirectURL()).to.be.instanceOf(Error)
  })
  it('should return redirect URL with default e-service id', () => {
    const target = 'target'
    expect(authClient.createRedirectURL(target)).to.equal(
      authClient.idpLoginURL +
      '?RequestBinding=HTTPArtifact' +
      '&ResponseBinding=HTTPArtifact' +
      '&PartnerId=' +
      encodeURI(authClient.partnerEntityId) +
      '&Target=' +
      encodeURI(target) +
      '&NameIdFormat=Email' +
      '&esrvcID=' +
      authClient.esrvcID
    )
  })
  it('should return redirect URL with specified e-service id', () => {
    const target = 'target'
    const esrvcID = 'otherId'
    expect(authClient.createRedirectURL(target, esrvcID)).to.equal(
      authClient.idpLoginURL +
      '?RequestBinding=HTTPArtifact' +
      '&ResponseBinding=HTTPArtifact' +
      '&PartnerId=' +
      encodeURI(authClient.partnerEntityId) +
      '&Target=' +
      encodeURI(target) +
      '&NameIdFormat=Email' +
      '&esrvcID=' +
      esrvcID
    )
  })
})
