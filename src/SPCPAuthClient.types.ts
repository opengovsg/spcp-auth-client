import xpath, { XPathSelect } from 'xpath'

export interface AuthClientConfig {
  partnerEntityId: string
  idpLoginURL: string
  idpEndpoint: string
  esrvcID: string
  appCert: string | Buffer
  appKey: string | Buffer
  appEncryptionKey?: string | Buffer
  spcpCert: string | Buffer
  extract?: (attributeElements: xpath.SelectedValue[]) => Record<string, string>
}

export type ArtifactResolveWithErr = {
  artifactResolve: string | null
  signingError: Error | null
}

export type IsVerifiedWithErr = {
  isVerified: boolean | null
  verificationError: string | string[] | null
}

export type AttributesWithErr = {
  attributes: Record<string, unknown> | null
  decryptionError: Error | null
}

export type NestedError = Error & { cause: unknown }

export type GetAttributesCallback = (
  err: Error | null,
  data:
    | { relayState: string, attributes?: Record<string, unknown> }
    | null
) => void

export type XpathNode = Parameters<XPathSelect>[1]
