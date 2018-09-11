const { expect } = require('chai')
const fs = require('fs')
const xmlCrypto = require('xml-crypto')
const xpath = require('xpath')
const { DOMParser } = require('xmldom')

const { SignedXml, FileKeyInfo } = xmlCrypto
const SPCPAuthClient = require('../SPCPAuthClient.class')
const domParser = new DOMParser()

describe('SPCPAuthClient - Signature Tests', () => {
  const authClient = new SPCPAuthClient({
    partnerEntityId: 'partnerEntityId',
    idpEndpoint: 'idpEndpoint',
    idpLoginURL: 'idpLoginURL',
    appKey: fs.readFileSync('./test/fixtures/certs/key.pem'),
    appCert: 'appCert',
    spcpCert: fs.readFileSync('./test/fixtures/certs/spcp.crt'),
    esrvcID: 'esrvcID',
  })

  const artifact = '<ArtifactResolve>value</ArtifactResolve>'
  const response = fs.readFileSync(
    './test/fixtures/saml/unsigned-response.xml', 'utf8'
  )

  const signatureTargets = {
    response: {
      location: {
        reference: "//*[local-name(.)='Response']/*[local-name(.)='Issuer']",
        action: 'after',
      },
      reference: "//*[local-name(.)='Response']",
    },
    assertion: {
      location: {
        reference: "//*[local-name(.)='Assertion']/*[local-name(.)='Issuer']",
        action: 'after',
      },
      reference: "//*[local-name(.)='Assertion']",
    },
  }

  const dom = xmlString => domParser.parseFromString(xmlString)

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

  it('should create a verifiable SAML signature', () => {
    const { artifactResolve, signingError } = authClient.signXML(artifact)

    expect(signingError).to.equal(null)

    const [ artifactResolvePayload ] =
      xpath.select("//*[local-name(.)='ArtifactResolve']", dom(artifactResolve))

    const verifier = new SignedXml()
    verifier.keyInfoProvider =
      new FileKeyInfo('./test/fixtures/certs/server.crt')

    const [ signature ] = xpath.select(
      "//*[local-name(.)='Signature']",
      artifactResolvePayload
    )

    verifier.loadSignature(signature.toString())
    const verified = verifier.checkSignature(artifactResolvePayload.toString())
    expect(verified, verifier.validationErrors).to.equal(true)
  })

  it('should flag signingErrors if signing fails', () => {
    const badClient = new SPCPAuthClient({
      partnerEntityId: 'partnerEntityId',
      idpEndpoint: 'idpEndpoint',
      idpLoginURL: 'idpLoginURL',
      appKey: 'badKey',
      appCert: 'appCert',
      spcpCert: 'spcpCert',
      esrvcID: 'esrvcID',
    })

    const { artifactResolve, signingError } = badClient.signXML(artifact)
    expect(signingError).to.not.equal(null)
    expect(artifactResolve).to.equal(null)
  })

  it('should reject responses signed only once by SingPass/CorpPass', () => {
    const signedPackage = prepareSignedXml(
      response,
      signatureTargets.response
    )

    const { isVerified, verificationError } = authClient.verifyXML(signedPackage)
    expect(isVerified).to.equal(null)
    expect(verificationError).to.equal('Artifact Response must contain 2 signatures')
  })

  it('should reject responses doubly signed by SingPass/CorpPass with bad response signature ', () => {
    // Sign the response before the assertion to get two signatures,
    // but rendering the response signature bad by getting the sig order wrong
    const signedPackage = prepareSignedXml(
      response,
      signatureTargets.response,
      signatureTargets.assertion
    )

    const { isVerified, verificationError } = authClient.verifyXML(signedPackage)
    expect(isVerified).to.equal(null)
    expect(verificationError).to.not.equal(null)
  })

  it('should reject responses doubly signed by SingPass/CorpPass with bad assertion signature ', () => {
    const signedPackage = prepareSignedXml(
      response,
      signatureTargets.assertion,
      signatureTargets.response
    )

    const signatureValue = xpath.select(
      "string(//*[local-name(.)='Assertion']/*[local-name(.)='Signature']/*[local-name(.)='SignatureValue'])",
      dom(signedPackage)
    )

    const tamperedPackage = signedPackage.replace(signatureValue, 'tampered')
    const { isVerified, verificationError } = authClient.verifyXML(tamperedPackage)
    expect(isVerified).to.equal(null)
    expect(verificationError).to.not.equal(null)
  })

  it('should accept responses doubly signed by SingPass/CorpPass', () => {
    const signedPackage = prepareSignedXml(
      response,
      signatureTargets.assertion,
      signatureTargets.response
    )

    const { isVerified, verificationError } = authClient.verifyXML(signedPackage)
    expect(isVerified, verificationError).to.equal(true)
  })
})
