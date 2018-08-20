const xmlCrypto = require('xml-crypto')
const xpath = require('xpath')
const xmldom = require('xmldom')
const xmlEnc = require('xml-encryption')
const request = require('request')
const _ = require('lodash')
const jwt = require('jsonwebtoken')

/**
 * Helper class to assist authenication process with spcp servers
 */
class SPCPAuthClient {
  /**
   * Creates an instance of the class
   * This instance will create and verify JSON Web Tokens (JWT) using RSA-256
   * @param  {Object} config - Configuration parameters for instance
   * @param  {String} config.partnerEntityId - the partner entity id
   * @param  {String} config.idpLoginURL - the fully-qualified SingPass/CorpPass IDP url to redirect login attempts to
   * @param  {String} config.idpEndpoint - the fully-qualified SingPass/CorpPass IDP url for out-of-band (OOB) authentication
   * @param  {String} config.esrvcID - the e-service identifier registered with SingPass/CorpPass
   * @param  {(String|Buffer)} config.appCert - the e-service public certificate issued to SingPass/CorpPass
   * @param  {(String|Buffer)} config.appKey - the e-service certificate private key
   * @param  {String} config.spcpCert - the public certificate of SingPass/CorpPass, for OOB authentication
   */
  constructor (config) {
    const PARAMS = [
      'partnerEntityId',
      'idpEndpoint',
      'idpLoginURL',
      'appKey',
      'appCert',
      'spcpCert',
      'esrvcID',
    ]

    for (let param of PARAMS) {
      if (config[param]) {
        this[param] = config[param]
      } else {
        throw new Error(param + ' undefined')
      }
    }
    this.jwtAlgorithm = 'RS256'
  }

  /**
   * Generates redirect URL to Official SPCP log-in page
   * @param  {String} target - State to pass SPCP
   * @param  {String} esrvcID - Optional e-service Id
   * @return {String} redirectURL - SPCP page to redirect to
   */
  createRedirectURL (target, esrvcID) {
    if (!target) {
      return new Error('Target undefined')
    }
    return (
      this.idpLoginURL +
      '?RequestBinding=HTTPArtifact' +
      '&ResponseBinding=HTTPArtifact' +
      '&PartnerId=' +
      encodeURI(this.partnerEntityId) +
      '&Target=' +
      encodeURI(target) +
      '&NameIdFormat=Email' +
      '&esrvcID=' +
      (esrvcID || this.esrvcID)
    )
  }

  /**
   * Creates a JSON Web Token (JWT) for a web session authenticated by SingPass/CorpPass
   * @param  {Object} payload - Payload to sign
   * @param  {(String|Integer)} expiresIn - The lifetime of the jwt token, fed to jsonwebtoken
   * @return {String} the created JWT
   */
  createJWT (payload, expiresIn) {
    return jwt.sign(
      payload,
      this.appKey,
      { expiresIn, algorithm: this.jwtAlgorithm }
    )
  }

  /**
   * Verifies a JWT for SingPass/CorpPass-authenticated session
   * @param  {String} jwtToken - The JWT to verify
   * @param  {Function} callback - Optional - Callback called with decoded payload
   * @return {Object} the decoded payload if no callback supplied, or nothing otherwise
   */
  verifyJWT (jwtToken, callback) {
    return jwt.verify(
      jwtToken,
      this.appCert,
      { algorithms: [this.jwtAlgorithm] },
      callback
    )
  }

  /**
   * Signs xml with provided key
   * @param  {String} xml - Xml containing artifact to be signed
   * @return {String} artifactResolve - Artifact resolve to send to SPCP
   */
  signXML (xml) {
    let sig = new xmlCrypto.SignedXml()

    let transforms = [
      'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
      'http://www.w3.org/2001/10/xml-exc-c14n#',
    ]
    let digestAlgorithm = 'http://www.w3.org/2001/04/xmlenc#sha256'
    let xpath = "//*[local-name(.)='ArtifactResolve']"
    sig.addReference(xpath, transforms, digestAlgorithm)

    sig.signingKey = this.appKey
    sig.signatureAlgorithm = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'

    let artifactResolve = null
    let signingError = null

    try {
      sig.computeSignature(xml, { prefix: 'ds' })
      artifactResolve =
        '<?xml version="1.0" encoding="UTF-8"?>' +
        '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">' +
        '<soapenv:Header />' +
        '<soapenv:Body>' +
        sig.getSignedXml() +
        '</soapenv:Body>' +
        '</soapenv:Envelope>'
    } catch (err) {
      signingError = err
    }

    return { artifactResolve, signingError }
  }

  /**
   * Verifies signatures in artifact response from SPCP based on public key of SPCP
   * @param  {String} xml - Artifact Response from SPCP
   * @return {Boolean} sig0 - Boolean value of whether signatures in artifact response are verified
   */
  verifyXML (xml) {
    /**
     * Creates KeyInfo function
     * @param  {String} key - Public key of SPCP
     */
    function KeyInfo (key) {
      this.getKey = function () {
        return key
      }
    }

    let signatures = xpath.select(
      "//*[local-name(.)='Signature']",
      new xmldom.DOMParser().parseFromString(xml)
    )

    let verifier
    let sig0
    let sig1
    verifier = new xmlCrypto.SignedXml()
    verifier.keyInfoProvider = new KeyInfo(this.spcpCert)

    let isVerified = null
    let verificationError = null

    // Artifact Response should contain 2 signatures
    if (!signatures || signatures.length !== 2) {
      verificationError = 'Artifact Response must contain 2 signatures'
      return { isVerified, verificationError }
    }

    // Check Signature 0
    verifier.loadSignature(signatures[0].toString())
    sig0 = verifier.checkSignature(xml)
    if (!sig0) {
      verificationError = verifier.validationErrors
      return { isVerified, verificationError }
    }

    // Check Signature 1
    verifier.loadSignature(signatures[1].toString())
    sig1 = verifier.checkSignature(xml)
    if (!sig1) {
      verificationError = verifier.validationErrors
      return { isVerified, verificationError }
    }

    isVerified = sig0 && sig1
    return { isVerified, verificationError }
  }

  /**
   * Decrypts encrypted data in artifact response from SPCP based on app private key
   * @param  {String} encryptedData - Encrypted data in artifact response from SPCP
   * @return {String} username - Decrypted username from encrypted data
   */
  decryptXML (encryptedData) {
    let decryptedData
    let userName = null
    let decryptionError = null
    let options = {
      key: this.appKey,
    }

    // TODO: do not mutate input variables; have separate variables for each decrypted thing
    xmlEnc.decrypt(encryptedData.toString(), options, function (err, result) {
      if (err) {
        decryptionError = err
        return { userName, decryptionError }
      } else {
        decryptedData = new xmldom.DOMParser().parseFromString(result)
        encryptedData = xpath.select(
          "//*[local-name(.)='EncryptedData']",
          decryptedData
        )
      }
      xmlEnc.decrypt(encryptedData.toString(), options, function (err, result) {
        if (err) {
          decryptionError = err
          return { userName, decryptionError }
        } else {
          decryptedData = new xmldom.DOMParser().parseFromString(result)
          userName = _.get(decryptedData, ['documentElement', 'childNodes', '0', 'data'], null)
        }
      })
    })
    return { userName, decryptionError }
  }

  /**
   * Creates a nested error object
   * @param  {String} errMsg - A human readable description of the error
   * @param  {String} cause - The error stack
   * @return {String} nestedError - Nested error object
   */
  makeNestedError (errMsg, cause) {
    const nestedError = new Error(errMsg)
    nestedError.cause = cause
    return nestedError
  }

  /**
   * Carries artifactResolve and artifactResponse protocol
   * @param  {String} samlArt - Token returned by spcp server via browser redirect
   * @param  {String} relayState - State passed in on intial spcp redirect
   * @param {Function} callback - Callback function with inputs error and UserName
   */
  getUserName (samlArt, relayState, callback) {
    // Step 1: Check if relay state present
    if (!samlArt || !relayState) {
      callback(
        new Error('Error in Step 1: Callback or saml artifact not present'),
        { relayState }
      )
    } else {
      // Step 2: Form Artifact Resolve with Artifact and Sign
      const xml =
        '<samlp:ArtifactResolve xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"' +
        'xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"' +
        ' Destination="' +
        this.idpEndpoint +
        '" ID="_0" Version="2.0">' +
        '<saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">' +
        this.partnerEntityId +
        '</saml:Issuer>' +
        '<samlp:Artifact>' +
        samlArt +
        '</samlp:Artifact>' +
        '</samlp:ArtifactResolve>'
      const { artifactResolve, signingError } = this.signXML(xml)

      if (!artifactResolve) {
        const nestedError = this.makeNestedError(
          'Error in Step 2: Form Artifact Resolve with Artifact and Sign',
          signingError
        )
        callback(nestedError, { relayState })
      } else {
        // Step 3: Send Artifact Resolve over OOB
        const requestOptions = {
          headers: {
            'content-type': 'text/xml; charset=utf-8',
            SOAPAction: 'http://www.oasis-open.org/committees/security',
          },
          url: this.idpEndpoint,
          body: artifactResolve,
        }
        request.post(requestOptions, (resolveError, response, body) => {
          if (resolveError) {
            const nestedError = this.makeNestedError(
              'Error in Step 3: Send Artifact Resolve over OOB',
              resolveError
            )
            callback(nestedError, { relayState })
          } else {
            // Step 4: Verify Artifact Response
            const { isVerified, verificationError } = this.verifyXML(body)
            if (!isVerified) {
              const nestedError = this.makeNestedError(
                'Error in Step 4: Verify Artifact Response',
                verificationError
              )
              callback(nestedError, { relayState })
            } else {
              // Step 5: Decrypt Artifact Response
              let encryptedData = xpath.select(
                "//*[local-name(.)='EncryptedData']",
                new xmldom.DOMParser().parseFromString(body)
              )
              const { userName, decryptionError } = this.decryptXML(encryptedData)
              if (userName) {
                callback(null, { userName, relayState })
              } else {
                const nestedError = this.makeNestedError(
                  'Error in Step 5: Decrypt Artifact Response',
                  decryptionError
                )
                callback(nestedError, { relayState })
              }
            }
          }
        })
      }
    }
  }
}

module.exports = SPCPAuthClient
