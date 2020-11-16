"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
var base_64_1 = __importDefault(require("base-64"));
var jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
var request_1 = __importDefault(require("request"));
var xml_crypto_1 = __importDefault(require("xml-crypto"));
var xml2json_light_1 = require("xml2json-light");
var xmldom_1 = __importDefault(require("xmldom"));
var xml_encryption_1 = __importDefault(require("xml-encryption"));
var xpath_1 = __importDefault(require("xpath"));
var lodash_1 = require("lodash");
/**
 * Helper class to assist authenication process with spcp servers
 */
var SPCPAuthClient = /** @class */ (function () {
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
     * @param  {(String|Buffer)} config.appEncryptionKey - the e-service private key used decrypt  artifact response from SPCP, if different from appKey
     * @param  {(String|Buffer)} config.spcpCert - the public certificate of SingPass/CorpPass, for OOB authentication
     * @param  {String} config.extract - Optional function for extracting information from Artifact Response
     */
    function SPCPAuthClient(config) {
        var PARAMS = [
            'partnerEntityId',
            'idpEndpoint',
            'idpLoginURL',
            'appKey',
            'appCert',
            'spcpCert',
            'esrvcID',
        ];
        var missingParams = lodash_1.difference(PARAMS, Object.keys(config));
        if (missingParams.length > 0) {
            throw new Error(missingParams.join(',') + " undefined");
        }
        this.partnerEntityId = config.partnerEntityId;
        this.idpLoginURL = config.idpLoginURL;
        this.idpEndpoint = config.idpEndpoint;
        this.esrvcID = config.esrvcID;
        this.appCert = config.appCert;
        this.appKey = config.appKey;
        this.spcpCert = config.spcpCert;
        this.appEncryptionKey = config.appEncryptionKey || config.appKey;
        this.extract = config.extract || SPCPAuthClient.extract.SINGPASS;
        this.jwtAlgorithm = 'RS256';
    }
    /**
     * Generates redirect URL to Official SPCP log-in page
     * @param  {String} target - State to pass SPCP
     * @param  {String} [esrvcID] - Optional e-service Id
     * @return {(String|Error)} redirectURL - SPCP page to redirect to or error if target was not given
     */
    SPCPAuthClient.prototype.createRedirectURL = function (target, esrvcID) {
        if (!target) {
            return new Error('Target undefined');
        }
        return (this.idpLoginURL +
            '?RequestBinding=HTTPArtifact' +
            '&ResponseBinding=HTTPArtifact' +
            '&PartnerId=' +
            encodeURI(this.partnerEntityId) +
            '&Target=' +
            encodeURI(target) +
            '&NameIdFormat=Email' +
            '&esrvcID=' +
            (esrvcID || this.esrvcID));
    };
    /**
     * Creates a JSON Web Token (JWT) for a web session authenticated by SingPass/CorpPass
     * @param  {Object} payload - Payload to sign
     * @param  {(String|Integer)} expiresIn - The lifetime of the jwt token, fed to jsonwebtoken
     * @return {String} the created JWT
     */
    SPCPAuthClient.prototype.createJWT = function (payload, expiresIn) {
        return jsonwebtoken_1.default.sign(payload, this.appKey, { expiresIn: expiresIn, algorithm: this.jwtAlgorithm });
    };
    /**
     * Verifies a JWT for SingPass/CorpPass-authenticated session
     * @param  {String} jwtToken - The JWT to verify
     * @param  {Function} [callback] - Optional - Callback called with decoded payload
     * @return {Object} the decoded payload if no callback supplied, or nothing otherwise
     */
    SPCPAuthClient.prototype.verifyJWT = function (jwtToken, callback) {
        return jsonwebtoken_1.default.verify(jwtToken, this.appCert, { algorithms: [this.jwtAlgorithm] }, callback);
    };
    /**
     * Signs xml with provided key
     * @param  {String} xml - Xml containing artifact to be signed
     * @return {Object} { artifactResolve, signingError } - Artifact resolve to send to SPCP
     * and error if there was an error.
     */
    SPCPAuthClient.prototype.signXML = function (xml) {
        var sig = new xml_crypto_1.default.SignedXml();
        var transforms = [
            'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
            'http://www.w3.org/2001/10/xml-exc-c14n#',
        ];
        var digestAlgorithm = 'http://www.w3.org/2001/04/xmlenc#sha256';
        var xpath = "//*[local-name(.)='ArtifactResolve']";
        sig.addReference(xpath, transforms, digestAlgorithm);
        sig.signingKey = this.appKey;
        sig.signatureAlgorithm = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
        var artifactResolve = null;
        var signingError = null;
        try {
            sig.computeSignature(xml, { prefix: 'ds' });
            artifactResolve =
                '<?xml version="1.0" encoding="UTF-8"?>' +
                    '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">' +
                    '<soapenv:Header />' +
                    '<soapenv:Body>' +
                    sig.getSignedXml() +
                    '</soapenv:Body>' +
                    '</soapenv:Envelope>';
        }
        catch (err) {
            signingError = err;
        }
        return { artifactResolve: artifactResolve, signingError: signingError };
    };
    /**
     * Verifies signatures in artifact response from SPCP based on public key of SPCP
     * @param  {String} xml - Artifact Response from SPCP
     * @return {Object} { isVerified, verificationError } - Boolean value of whether
     * signatures in artifact response are verified, and error if the operation failed.
     */
    SPCPAuthClient.prototype.verifyXML = function (xml) {
        /**
         * Creates KeyInfo function
         * @param  {String|Buffer} key - Public key of SPCP
         */
        var KeyInfo = /** @class */ (function () {
            function KeyInfo(key) {
                this.key = key.toString();
            }
            KeyInfo.prototype.getKey = function () {
                return this.key;
            };
            return KeyInfo;
        }());
        var signatures = xpath_1.default.select("//*[local-name(.)='Signature']", new xmldom_1.default.DOMParser().parseFromString(xml));
        var verifier = new xml_crypto_1.default.SignedXml();
        verifier.keyInfoProvider = new KeyInfo(this.spcpCert);
        var isVerified = null;
        var verificationError = null;
        // Artifact Response should contain 2 signatures
        if (!signatures || signatures.length !== 2) {
            verificationError = 'Artifact Response must contain 2 signatures';
            return { isVerified: isVerified, verificationError: verificationError };
        }
        // Check Signature 0
        verifier.loadSignature(signatures[0].toString());
        var sig0 = verifier.checkSignature(xml);
        if (!sig0) {
            verificationError = verifier.validationErrors;
            return { isVerified: isVerified, verificationError: verificationError };
        }
        // Check Signature 1
        verifier.loadSignature(signatures[1].toString());
        var sig1 = verifier.checkSignature(xml);
        if (!sig1) {
            verificationError = verifier.validationErrors;
            return { isVerified: isVerified, verificationError: verificationError };
        }
        isVerified = sig0 && sig1;
        return { isVerified: isVerified, verificationError: verificationError };
    };
    /**
     * Decrypts encrypted data in artifact response from SPCP based on app private key
     * @param  {String} encryptedData - Encrypted data in artifact response from SPCP
     * @return {Object} { attributes, decryptionError } - attributes is a k-v map of
     * attributes obtained from the artifact, and decryptionError is the error if the
     * operation failed.
     */
    SPCPAuthClient.prototype.decryptXML = function (encryptedData) {
        var _this = this;
        return xml_encryption_1.default.decrypt(encryptedData, {
            key: this.appEncryptionKey,
        }, function (err, decryptedData) {
            var attributes = null;
            var decryptionError = null;
            if (err) {
                decryptionError = err;
            }
            else {
                var attributeElements = xpath_1.default.select('//*[local-name(.)=\'Attribute\']', new xmldom_1.default.DOMParser().parseFromString(decryptedData));
                attributes = _this.extract(attributeElements);
            }
            return { attributes: attributes, decryptionError: decryptionError };
        });
    };
    /**
     * Creates a nested error object
     * @param  {String} errMsg - A human readable description of the error
     * @param  {String|Object} cause - The error stack
     * @return {Error} nestedError - Nested error object
     */
    SPCPAuthClient.prototype.makeNestedError = function (errMsg, cause) {
        var nestedError = new Error(errMsg);
        nestedError.cause = cause;
        return nestedError;
    };
    /**
     * Carries artifactResolve and artifactResponse protocol
     * @param  {String} samlArt - Token returned by spcp server via browser redirect
     * @param  {String} relayState - State passed in on intial spcp redirect
     * @param {Function} callback - Callback function with inputs error and UserName
     */
    SPCPAuthClient.prototype.getAttributes = function (samlArt, relayState, callback) {
        var _this = this;
        // Step 1: Check if relay state present
        if (!samlArt || !relayState) {
            callback(new Error('Error in Step 1: Callback or saml artifact not present'), { relayState: relayState });
        }
        else {
            // Step 2: Form Artifact Resolve with Artifact and Sign
            var xml = '<samlp:ArtifactResolve xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ' +
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
                '</samlp:ArtifactResolve>';
            var _a = this.signXML(xml), artifactResolve = _a.artifactResolve, signingError = _a.signingError;
            if (!artifactResolve) {
                var nestedError = this.makeNestedError('Error in Step 2: Form Artifact Resolve with Artifact and Sign', signingError);
                callback(nestedError, { relayState: relayState });
            }
            else {
                // Step 3: Send Artifact Resolve over OOB
                var requestOptions = {
                    headers: {
                        'content-type': 'text/xml; charset=utf-8',
                        SOAPAction: 'http://www.oasis-open.org/committees/security',
                    },
                    url: this.idpEndpoint,
                    body: artifactResolve,
                };
                request_1.default.post(requestOptions, function (resolveError, response, body) {
                    if (resolveError) {
                        var nestedError = _this.makeNestedError('Error in Step 3: Send Artifact Resolve over OOB', resolveError);
                        callback(nestedError, { relayState: relayState });
                    }
                    else {
                        // Step 4: Verify Artifact Response
                        var _a = _this.verifyXML(body), isVerified = _a.isVerified, verificationError = _a.verificationError;
                        if (!isVerified) {
                            var nestedError = _this.makeNestedError('Error in Step 4: Verify Artifact Response', verificationError);
                            callback(nestedError, { relayState: relayState });
                        }
                        else {
                            // Step 5: Decrypt Artifact Response
                            var encryptedData = xpath_1.default.select("//*[local-name(.)='EncryptedData']", new xmldom_1.default.DOMParser().parseFromString(body)).toString();
                            var _b = _this.decryptXML(encryptedData), attributes = _b.attributes, decryptionError = _b.decryptionError;
                            if (attributes) {
                                callback(null, { attributes: attributes, relayState: relayState });
                            }
                            else {
                                var nestedError = _this.makeNestedError('Error in Step 5: Decrypt Artifact Response', decryptionError);
                                callback(nestedError, { relayState: relayState });
                            }
                        }
                    }
                });
            }
        }
    };
    return SPCPAuthClient;
}());
// Functions for extracting attributes from Artifact Response
SPCPAuthClient.extract = {
    CORPPASS: function (_a) {
        var element = _a[0];
        var cpXMLBase64 = xpath_1.default.select('string(./*[local-name(.)=\'AttributeValue\'])', element).toString();
        return xml2json_light_1.xml2json(base_64_1.default.decode(cpXMLBase64));
    },
    SINGPASS: function (attributeElements) { return attributeElements.reduce(function (attributes, element) {
        var key = xpath_1.default.select('string(./@Name)', element).toString();
        var value = xpath_1.default.select('string(./*[local-name(.)=\'AttributeValue\'])', element);
        attributes[key] = value;
        return attributes;
    }, {}); },
};
module.exports = SPCPAuthClient;
