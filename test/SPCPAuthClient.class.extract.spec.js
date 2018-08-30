const { expect } = require('chai')
const base64 = require('base-64')
const xpath = require('xpath')
const xmldom = require('xmldom')

const { extract: { SINGPASS: singPass, CORPPASS: corpPass } } = require('../SPCPAuthClient.class')

describe('SPCPAuthClient.extract - Attributes Extract Tests', () => {
  it('should correctly return SingPass attributes', () => {
    const expected = {
      UserName: 'S1234567A',
      MobileNumber: '91234567',
    }
    const attributeStatementString = `
      <AttributeStatement>
        <Attribute Name="UserName">
          <AttributeValue>${expected.UserName}</AttributeValue>
        </Attribute>
        <Attribute Name="MobileNumber">
          <AttributeValue>${expected.MobileNumber}</AttributeValue>
        </Attribute>
      </AttributeStatement>
    `
    const attributeElements = xpath.select(
      `//*[local-name(.)='Attribute']`,
      new xmldom.DOMParser().parseFromString(attributeStatementString)
    )

    expect(singPass(attributeElements)).to.eql(expected)
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
    const attributeStatementString = `
      <AttributeStatement>
        <Attribute Name="${entityId}">
          <AttributeValue>${base64.encode(corpPassXMLString)}</AttributeValue>
        </Attribute>
      </AttributeStatement>
    `
    const attributeElements = xpath.select(
      `//*[local-name(.)='Attribute']`,
      new xmldom.DOMParser().parseFromString(attributeStatementString)
    )

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
    expect(corpPass(attributeElements)).to.eql(expected)
  })
})
