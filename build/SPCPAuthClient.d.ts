/// <reference types="node" />
import jwt from 'jsonwebtoken';
import { ArtifactResolveWithErr, AttributesWithErr, GetAttributesCallback, AuthClientConfig, IsVerifiedWithErr, NestedError, XPathNode } from './SPCPAuthClient.types';
/**
 * Helper class to assist authenication process with spcp servers
 */
declare class SPCPAuthClient {
    partnerEntityId: string;
    idpLoginURL: string;
    idpEndpoint: string;
    esrvcID: string;
    appCert: string | Buffer;
    appKey: string | Buffer;
    appEncryptionKey: string | Buffer;
    spcpCert: string | Buffer;
    extract: (attributeElements: XPathNode[]) => Record<string, unknown>;
    jwtAlgorithm: jwt.Algorithm;
    static extract: {
        SINGPASS: (attributeElements: XPathNode[]) => Record<string, unknown>;
        CORPPASS: (attributeElements: XPathNode[]) => Record<string, unknown>;
    };
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
    constructor(config: AuthClientConfig);
    /**
     * Generates redirect URL to Official SPCP log-in page
     * @param  {String} target - State to pass SPCP
     * @param  {String} [esrvcID] - Optional e-service Id
     * @return {(String|Error)} redirectURL - SPCP page to redirect to or error if target was not given
     */
    createRedirectURL(target: string, esrvcID?: string): string | Error;
    /**
     * Creates a JSON Web Token (JWT) for a web session authenticated by SingPass/CorpPass
     * @param  {Object} payload - Payload to sign
     * @param  {(String|Integer)} expiresIn - The lifetime of the jwt token, fed to jsonwebtoken
     * @return {String} the created JWT
     */
    createJWT(payload: Record<string, unknown> | unknown[], expiresIn: string | number): string;
    /**
     * Verifies a JWT for SingPass/CorpPass-authenticated session
     * @param  {String} jwtToken - The JWT to verify
     * @param  {Function} [callback] - Optional - Callback called with decoded payload
     * @return {Object} the decoded payload if no callback supplied, or nothing otherwise
     */
    verifyJWT<T>(jwtToken: string, callback?: jwt.VerifyCallback<T>): T;
    /**
     * Signs xml with provided key
     * @param  {String} xml - Xml containing artifact to be signed
     * @return {Object} { artifactResolve, signingError } - Artifact resolve to send to SPCP
     * and error if there was an error.
     */
    signXML(xml: string): ArtifactResolveWithErr;
    /**
     * Verifies signatures in artifact response from SPCP based on public key of SPCP
     * @param  {String} xml - Artifact Response from SPCP
     * @return {Object} { isVerified, verificationError } - Boolean value of whether
     * signatures in artifact response are verified, and error if the operation failed.
     */
    verifyXML(xml: string): IsVerifiedWithErr;
    /**
     * Decrypts encrypted data in artifact response from SPCP based on app private key
     * @param  {String} encryptedData - Encrypted data in artifact response from SPCP
     * @return {Object} { attributes, decryptionError } - attributes is a k-v map of
     * attributes obtained from the artifact, and decryptionError is the error if the
     * operation failed.
     */
    decryptXML(encryptedData: string): AttributesWithErr;
    /**
     * Creates a nested error object
     * @param  {String} errMsg - A human readable description of the error
     * @param  {String|Object} cause - The error stack
     * @return {Error} nestedError - Nested error object
     */
    makeNestedError(errMsg: string, cause: unknown): NestedError;
    /**
     * Carries artifactResolve and artifactResponse protocol
     * @param  {String} samlArt - Token returned by spcp server via browser redirect
     * @param  {String} relayState - State passed in on intial spcp redirect
     * @param {Function} callback - Callback function with inputs error and UserName
     */
    getAttributes(samlArt: string, relayState: string, callback: GetAttributesCallback): void;
}
export = SPCPAuthClient;
