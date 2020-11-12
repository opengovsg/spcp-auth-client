declare module 'xml-encryption' {
  interface Options {
    key: string | Buffer
    disallowDecryptionWithInsecureAlgorithm?: boolean
    warnInsecureAlgorithm?: boolean
  }
  type Callback<T> = (err: Error, decryptedData: string) => T
  export function decrypt<T>(encryptedData: string, options: Options, cb: Callback<T>): T
}
