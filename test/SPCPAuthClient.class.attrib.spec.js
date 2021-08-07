const { expect } = require('chai')
const fs = require('fs')
const { render } = require('mustache')
const axios = require('axios')
const sinon = require('sinon')
const xmlCrypto = require('xml-crypto')
const xmlEnc = require('xml-encryption')

const { encrypt } = xmlEnc
const { SignedXml } = xmlCrypto
const SPCPAuthClient = require('../build/SPCPAuthClient')

describe('SPCPAuthClient - getAttributes', () => {
  const authClient = new SPCPAuthClient({
    partnerEntityId: 'partnerEntityId',
    idpEndpoint: 'idpEndpoint',
    idpLoginURL: 'idpLoginURL',
    appKey: fs.readFileSync('./test/fixtures/certs/key.pem'),
    appEncryptionKey: fs.readFileSync('./test/fixtures/certs/key.pem'),
    appCert: 'appCert',
    spcpCert: fs.readFileSync('./test/fixtures/certs/spcp.crt'),
    esrvcID: 'esrvcID',
  })

  const input = { name: 'UserName', value: 'S1234567A' }
  const assertion = render(
    fs.readFileSync(
      './test/fixtures/saml/unsigned-assertion.xml', 'utf8'
    ),
    input
  )

  const signatureTargets = {
    response: {
      location: {
        reference: "//*[local-name(.)='Response']/*[local-name(.)='Issuer']",
        action: 'after',
      },
      reference: "//*[local-name(.)='Response']",
    },
    artifactResponse: {
      location: {
        reference: "//*[local-name(.)='ArtifactResponse']/*[local-name(.)='Issuer']",
        action: 'after',
      },
      reference: "//*[local-name(.)='ArtifactResponse']",
    },
  }

  const prepareSignedXml = (payload, ...targets) => {
    let result = payload
    for (const { reference, location } of targets) {
      const sig = new SignedXml()

      const transforms = [
        'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
        'http://www.w3.org/2001/10/xml-exc-c14n#',
      ]
      const digestAlgorithm = 'http://www.w3.org/2001/04/xmlenc#sha256'
      sig.addReference(reference, transforms, digestAlgorithm)
      sig.signingKey = fs.readFileSync('./test/fixtures/certs/spcp-key.pem')
      sig.signatureAlgorithm = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
      sig.computeSignature(result, { prefix: 'ds', location })
      result = sig.getSignedXml()
    }
    return result
  }

  let signedPackage

  before(done => {
    const options = {
      rsa_pub: fs.readFileSync('./test/fixtures/certs/key.pub'),
      pem: fs.readFileSync('./test/fixtures/certs/server.crt'),
      encryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#aes256-cbc',
      keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-1_5',
    }
    const callback = (err, data) => {
      if (err) {
        done(err)
      } else {
        const response = render(
          fs.readFileSync('./test/fixtures/saml/unsigned-response.xml', 'utf8'),
          {
            assertion: `<saml:EncryptedAssertion>${data}</saml:EncryptedAssertion>`,
          }
        )
        signedPackage = prepareSignedXml(
          response,
          signatureTargets.response,
          signatureTargets.artifactResponse
        )
        done()
      }
    }
    encrypt(assertion, options, callback)
  })

  afterEach(() => {
    if (typeof axios.post.restore === 'function') {
      axios.post.restore()
    }
  })

  it('should error on no SAMLArt', done => {
    authClient.getAttributes(undefined, 'relayState', (err, data) => {
      expect(err).to.be.instanceOf(Error)
      expect(data).to.eql({ relayState: 'relayState' })
      done()
    })
  })

  it('should error on no relayState', done => {
    authClient.getAttributes('artifact', undefined, (err, data) => {
      expect(err).to.be.instanceOf(Error)
      expect(data).to.eql({ relayState: undefined })
      done()
    })
  })

  it('should error on artifact resolve fail', done => {
    const signingError = new Error('sign')
    sinon.stub(authClient, 'signXML').returns({
      artifactResolve: undefined,
      signingError,
    })
    try {
      authClient.getAttributes('artifact', 'relayState', (err, data) => {
        expect(err).to.be.instanceOf(Error)
        expect(err.cause).to.equal(signingError)
        expect(data).to.eql({ relayState: 'relayState' })
        done()
      })
    } finally {
      authClient.signXML.restore()
    }
  })

  it('should error on POST fail', done => {
    const resolveError = new Error('sign')
    sinon.stub(axios, 'post').rejects(resolveError);
    authClient.getAttributes('artifact', 'relayState', (err, data) => {
      expect(err).to.be.instanceOf(Error)
      expect(err.cause).to.equal(resolveError)
      expect(data).to.eql({ relayState: 'relayState' })
      done()
    })
  })

  it('should error on verify fail', done => {
    sinon.stub(axios, 'post').resolves({ data: signedPackage })
    const verificationError = new Error('verify')
    sinon.stub(authClient, 'verifyXML').returns({
      isVerified: null,
      verificationError,
    })
    authClient.getAttributes('artifact', 'relayState', (err, data) => {
      expect(err).to.be.instanceOf(Error)
      expect(err.cause).to.equal(verificationError)
      expect(data).to.eql({ relayState: 'relayState' })

      authClient.verifyXML.restore()
      done()
    })
  })

  it('should error on decrypt fail', done => {
    sinon.stub(axios, 'post').resolves({ data: signedPackage })
    const decryptionError = new Error('decrypt')
    sinon.stub(xmlEnc, 'decrypt').callsFake((data, options, callback) => {
      expect(options.key).to.equal(authClient.appEncryptionKey)
      return callback(decryptionError)
    })
    authClient.getAttributes('artifact', 'relayState', (err, data) => {
      expect(err).to.be.instanceOf(Error)
      expect(err.cause).to.equal(decryptionError)
      expect(data).to.eql({ relayState: 'relayState' })

      xmlEnc.decrypt.restore();
      done()
    })
  })

  const expectedXML =
    '<samlp:ArtifactResolve xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ' +
    'xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"' +
    ' Destination="' +
    authClient.idpEndpoint +
    '" ID="_0" Version="2.0">' +
    '<saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">' +
    authClient.partnerEntityId +
    '</saml:Issuer>' +
    '<samlp:Artifact>artifact</samlp:Artifact>' +
    '</samlp:ArtifactResolve>'

  it('should get attributes', done => {
    sinon.stub(axios, 'post').resolves({ data: signedPackage })
    authClient.getAttributes('artifact', 'relayState', (err, data) => {
      expect(axios.post.getCall(0).args[0]).to.equal(authClient.idpEndpoint) // url
      expect(axios.post.getCall(0).args[1]).to.equal(authClient.signXML(expectedXML).artifactResolve) // body

      const attributes = { [input.name]: input.value }
      const expected = { relayState: 'relayState', attributes }
      expect(data, err).to.eql(expected)
      done()
    })
  })
})
