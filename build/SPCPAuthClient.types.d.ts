/// <reference types="node" />
import { XPathSelect } from 'xpath';
export declare type XPathNode = Parameters<XPathSelect>[1];
export interface AuthClientConfig {
    partnerEntityId: string;
    idpLoginURL: string;
    idpEndpoint: string;
    esrvcID: string;
    appCert: string | Buffer;
    appKey: string | Buffer;
    appEncryptionKey?: string | Buffer;
    spcpCert: string | Buffer;
    extract?: (attributeElements: XPathNode[]) => Record<string, unknown>;
}
export declare type ArtifactResolveWithErr = {
    artifactResolve: string | null;
    signingError: Error | null;
};
export declare type IsVerifiedWithErr = {
    isVerified: boolean | null;
    verificationError: string | string[] | null;
};
export declare type AttributesWithErr = {
    attributes: Record<string, unknown> | null;
    decryptionError: Error | null;
};
export declare type NestedError = Error & {
    cause: unknown;
};
export declare type GetAttributesCallback = (err: Error | null, data: {
    relayState: string;
    attributes?: Record<string, unknown>;
} | null) => void;
