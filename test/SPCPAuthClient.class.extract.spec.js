const base64 = require('base-64')
const { expect } = require('chai')
const fs = require('fs')
const { render } = require('mustache')
const xpath = require('xpath')
const xmldom = require('xmldom')

const { extract: { SINGPASS: singPass, CORPPASS: corpPass } } = require('../SPCPAuthClient.class')

describe('SPCPAuthClient.extract - Attributes Extract Tests', () => {
  const TEMPLATE = fs.readFileSync(
    './test/fixtures/saml/unsigned-assertion.xml', 'utf8'
  )

  const attributes = input => {
    const assertion = render(TEMPLATE, input)
    return xpath.select(
      '//*[local-name(.)=\'Attribute\']',
      new xmldom.DOMParser().parseFromString(assertion)
    )
  }

  it('should correctly return SingPass attributes', () => {
    const input = { name: 'UserName', value: 'S1234567A' }
    expect(singPass(attributes(input))).to.eql({ UserName: 'S1234567A' })
  })

  it('should correctly return CorpPass attributes', () => {
    const userId = 'S1234567A'
    const entityId = '123456789G'
    const serviceId = 'SPCP-TEST'
    const corpPassXMLString = `
      <UserInfo>
        <CPUID>${userId}</CPUID>
        <CPEntID>${entityId}</CPEntID>
      </UserInfo>
      <AuthAccess>
        <Result_Set>
          <ESrvc_Row_Count>1</ESrvc_Row_Count>
          <ESrvc_Result>
            <CPESrvcID>${serviceId}</CPESrvcID>
            <Auth_Result_Set>
              <Row_Count>1</Row_Count>
              <Row>
                <CPEntID_SUB>NULL</CPEntID_SUB>
                <CPRole>NULL</CPRole>
                <StartDate>2018-08-13</StartDate>
                <EndDate>9999-12-31</EndDate>
              </Row>
            </Auth_Result_Set>
          </ESrvc_Result>
        </Result_Set>
      </AuthAccess>
    `
    const input = { name: entityId, value: base64.encode(corpPassXMLString) }

    const expected = {
      UserInfo: {
        CPUID: userId,
        CPEntID: entityId,
      },
      AuthAccess: {
        Result_Set: {
          ESrvc_Row_Count: '1',
          ESrvc_Result: {
            CPESrvcID: serviceId,
            Auth_Result_Set: {
              Row_Count: '1',
              Row: {
                CPEntID_SUB: 'NULL',
                CPRole: 'NULL',
                StartDate: '2018-08-13',
                EndDate: '9999-12-31',
              },
            },
          },
        },
      },
    }
    expect(corpPass(attributes(input))).to.eql(expected)
  })
})
