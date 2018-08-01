const xmlCrypto = require("xml-crypto")
const xpath = require("xpath")
const DOMParser = require("xmldom").DOMParser
const xmlEnc = require("xml-encryption")
const request = require("request")

/**
 * Helper class to assist authenication process with spcp servers
 */
class NDIAuthClient {

  /**
   * Creates an instance of the class
   * @param  {Object} config - Configuration parameters for instance
   */
  constructor(config) {
    this.partnerEntityId = config.partnerEntityId
    this.idpEndpoint = config.idpEndpoint
    this.cookieMaxAge = config.cookieMaxAge
    this.formsgKey = config.formsgKey
    this.spcpCert = config.spcpCert
    if (this.formsgKey) {
      console.log('key defined 123')
    } else {
      console.log('key undefined 123')
    }
  }

  /**
   * Signs xml with provided key
   * @param  {String} xml - Xml containing artifact to be signed
   * @return {String} artifactResolve - Artifact resolve to send to SPCP
   */
  signXML(xml) {
    let sig = new xmlCrypto.SignedXml()

    let transforms = [
      "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
      "http://www.w3.org/2001/10/xml-exc-c14n#",
    ]
    let digestAlgorithm = "http://www.w3.org/2001/04/xmlenc#sha256"
    let xpath = "//*[local-name(.)='ArtifactResolve']"
    sig.addReference(xpath, transforms, digestAlgorithm)

    sig.signingKey = this.formsgKey
    sig.signatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"

    let artifactResolve = null
    let signingError = null

    try {
      sig.computeSignature(xml, { prefix: "ds" })
      artifactResolve =
        '<?xml version="1.0" encoding="UTF-8"?>' +
        '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">' +
        "<soapenv:Header />" +
        "<soapenv:Body>" +
        sig.getSignedXml() +
        "</soapenv:Body>" +
        "</soapenv:Envelope>"
    } catch (err) {
      signingError = err
    }

    return { artifactResolve, signingError }
  
  }

  /**
   * Verifies signatures in artifact response from SPCP based on public key of SPCP
   * @param  {String} xml - Artifact Response from SPCP
   * @param  {Array} signatures - Array of signatures extracted from artifact response
   * @return {Boolean} sig0 - Boolean value of whether signatures in artifact response are verified
   */
  verifyXML(xml, signatures) {
    /**
     * Creates KeyInfo function
     * @param  {String} key - Public key of SPCP
     */
    function KeyInfo(key) {
      this.getKey = function() {
        return Buffer.from(key, 'utf-8');
      }
    }

    let verifier
    let sig0
    let sig1
    verifier = new xmlCrypto.SignedXml()
    verifier.keyInfoProvider = new KeyInfo(this.spcpCert)

    let isVerified = null
    let verificationError = null

    // Artifact Response should contain 2 signatures
    if (!signatures || signatures.length != 2) {
      verificationError = "Artifact Response must contain 2 signatures"
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

    isVerified = sig0 & sig1
    return { isVerified, verificationError }
  }

  /**
   * Decrypts encrypted data in artifact response from SPCP based on FormSG private key
   * @param  {String} encryptedData - Encrypted data in artifact response from SPCP
   * @param  {String} key - FormSG private key
   * @return {String} nric - Decrypted NRIC from encrypted data
   */
  decryptXML(encryptedData) {
    let decryptedData
    let nric = null
    let decryptionError = null
    let options = {
      key: this.formsgKey,
    }

    // TODO: do not mutate input variables; have separate variables for each decrypted thing
    xmlEnc.decrypt(encryptedData.toString(), options, function(err, result) {
      if (err) {
        decryptionError = err
        return { nric, decryptionError }
      } else {
        decryptedData = new DOMParser().parseFromString(result)
        encryptedData = xpath.select(
          "//*[local-name(.)='EncryptedData']",
          decryptedData
        )
      }
      xmlEnc.decrypt(encryptedData.toString(), options, function(err, result) {
        if (err) {
          decryptionError = err
          return { nric, decryptionError }
        } else {
          decryptedData = new DOMParser().parseFromString(result)
          if (decryptedData) {
            if (decryptedData.documentElement) {
              if (decryptedData.documentElement.childNodes["0"]) {
                nric = decryptedData.documentElement.childNodes["0"].data
              }
            }
          }
        }
      })
    })
    return { nric, decryptionError }
  }

  /**
   * Carries artifactResolve and artifactResponse protocol
   * @param  {String} SAMLart - Token returned by spcp server via browser redirect
   * @param  {String} RelayState - State passed in on intial spcp redirect
   * @param {String} callback - Callback function with inputs error and NRIC
   */
  getNRIC(SAMLart, RelayState, callback) {
    console.log('step 1')
    // Step 1: Check if relay state present
    if (!SAMLart || !RelayState ) {
      callback(new Error("Error in Step 1: Callback or saml artifact not present"))
    } else {
      console.log('step 2')
      // Step 2: Form Artifact Resolve with Artifact and Sign
      const xml =
        '<samlp:ArtifactResolve xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"' +
        'xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"' +
        ' Destination="' +
        this.idpEndpoint +
        '" ID="_0" Version="2.0">' +
        '<saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">' +
        this.partnerEntityId +
        "</saml:Issuer>" +
        "<samlp:Artifact>" +
        SAMLart +
        "</samlp:Artifact>" +
        "</samlp:ArtifactResolve>"
      if (this.formsgKey) {
        console.log('key defined')
      } else {
        console.log('key undefined')
      }
      const { artifactResolve, signingError } = this.signXML(xml)

      if (!artifactResolve) {
        const nestedError = new Error("Error in Step 2: Form Artifact Resolve with Artifact and Sign")
        nestedError.cause = signingError
        callback(nestedError, null)
      } else {
        console.log('step 3')
        var verifyXML = this.verifyXML
        var decryptXML = this.decryptXML
        // Step 3: Send Artifact Resolve over OOB
        request.post(
          {
            headers: {
              "content-type": "text/xml; charset=utf-8",
              SOAPAction: "http://www.oasis-open.org/committees/security",
            },
            url: "/forms/spcp", //this.idpEndpoint,
            body: artifactResolve,
          },
          function(resolveError, response, body) {
            if (resolveError) {
              const nestedError = new Error("Error in Step 3: Send Artifact Resolve over OOB")
              nestedError.cause = resolveError
              callback(nestedError, null)
            } else {
              console.log('step 4')
              // Step 4: Verify Artifact Response
              let responseXML = body
              let responseDOM = new DOMParser().parseFromString(responseXML)
              let signatures = xpath.select(
                "//*[local-name(.)='Signature']",
                responseDOM
              )
              const { isVerified, verificationError } = verifyXML(responseXML, signatures)
              if (!isVerified) {
                const nestedError = new Error("Error in Step 4: Verify Artifact Response")
                nestedError.cause = verificationError
                callback(nestedError, null)
              } else {
                // Step 5: Decrypt Artifact Response
                let encryptedData = xpath.select(
                  "//*[local-name(.)='EncryptedData']",
                  responseDOM
                )
                const { nric, decryptionError } = decryptXML(encryptedData)
                let isValidNRIC = /^([STFGstfg]{1})+([0-9]{7})+([A-Za-z]{1})$/
                if (nric && isValidNRIC.test(nric)) {
                  callback(null, nric)
                } else {
                  const nestedError = new Error("Error in Step 5: Decrypt Artifact Response")
                  nestedError.cause = decryptionError
                  callback(nestedError, null)
                }
              }
            }
          }
        )
      }
    }
  }
}

module.exports = NDIAuthClient