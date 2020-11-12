import xpath from 'xpath'

export type XpathNode = Parameters<typeof xpath.select>[1]

export interface IConfig {
  partnerEntityId: string
  idpLoginURL: string
  idpEndpoint: string
  esrvcID: string
  appCert: string | Buffer
  appKey: string | Buffer
  appEncryptionKey?: string | Buffer
  spcpCert: string
  extract?: (attributeElements: XpathNode[]) => Record<string, string>
}
