# spcp-auth-client

A node.js library for SingPass and CorpPass, common authentication methods
for public-facing government systems in Singapore

## Quick Start

```javascript
const SPCPAuthClient = require('@opengovsg/spcp-auth-client')

const client = new SPCPAuthClient({
  partnerEntityId: '<your partner entity id>',
  idpLoginURL: '<the SingPass/CorpPass IDP url to redirect login attempts to>',
  idpEndpoint: '<the SingPass/CorpPass IDP url for out-of-band (OOB) authentication>',
  esrvcID: '<the e-service identifier registered with SingPass/CorpPass>',
  appCert: '<the e-service public certificate issued to SingPass/CorpPass>',
  appKey: '<the e-service certificate private key>',
  spcpCert: '<the public certificate of SingPass/CorpPass, for OOB authentication>',
  userNameXPath: '<custom XPath or SPCPAuthClient.xpaths.{CORPPASS_UEN or SINGPASS_NRIC (default)}>',
})

const express = require('express')

const POST_LOGIN_PAGE = '/<target-url-after-login>'

const app = express()

// If a user is logging in, redirect to SingPass/CorpPass
app.route('/login', (req, res) => {
  const redirectURL = client.createRedirectURL(POST_LOGIN_PAGE)
  res.status(200).send({ redirectURL })
})

// SingPass/CorpPass would eventually pass control back
// by GET-ing a pre-agreed endpoint, proceed to obtain the user's
// identity using out-of-band (OOB) authentication
app.route('/assert', (req, res) => {
  const { SAMLArt: samlArt, RelayState: relayState } = req.query
  client.getUserName(samlArt, relayState, (err, data) => {
    // If all is well and login occurs, the userName string is given
    // In all cases, the relayState as provided in getUserName() is given
    const { userName, relayState } = data
    if (err) {
      // Indicate through cookies or headers that an error has occurred
      res.cookie('login.error', err.message)
    } else {
      // Embed a session cookie or pass back some Authorization bearer token
      const FOUR_HOURS = 4 * 60 * 60 * 1000
      const jwt = client.createJWT(userName, FOUR_HOURS)
      res.cookie('connect.sid', jwt)
    }
    res.redirect(relayState)
  })
})

// Verify if session has been authenticated with our JWT
const isAuthenticated = (req, res, next) => {
  client.verifyJWT(req.cookies['connect.sid'], (err, data) => {
    if (err) {
      res.status(400).send('Unauthorized')
    } else {
      req.userName = data.userName
      next()
    }
  })
}
app.route(
  '/protected-route',
  isAuthenticated,
  // ...
)

```
## About SingPass/CorpPass and this package
SingPass and CorpPass are identity providers to provide a single set of login 
credentials for Singapore residents and Singapore-based corporate entities 
respectively. They are both based on [SAML 2.0](https://en.wikipedia.org/wiki/SAML_2.0), 
and interact with service providers through HTTP Artifact Binding. The artifact returned 
by the identity provider is a SAML Assertion consisting of attributes concerning the user.

What the attributes actually are depends on the identity provider:
 * SingPass will return the user's NRIC as the UserName attribute 
   (this is even if the user has a non-NRIC login id)
 * CorpPass will return an attribute whose name is the UEN of the
   corporate entity, and whose value is a base64-encoded payload of
   an XML document whose structure is defined in Section 4.4.3 of the 
   CorpPass Interface Specification v1.5

This package is a very lightweight implementation of the above, written after 
failing to find an npm package that supports artifact binding. It is meant for 
those who are solely focused on using SingPass or CorpPass as a sign-in mechanism, 
solely to retrieve either the NRIC or UEN, without being too concerned about 
other SAML 2.0 features. 

More full-fledged SAML 2.0 implementations for node.js include:

 * @socialtables/saml-protocol 
   ([GitHub](https://github.com/socialtables/saml-protocol), [npm](https://www.npmjs.com/package/@socialtables/saml-protocol)) - 
   a [port](https://medium.com/social-tables-tech/why-we-wrote-yet-another-saml-library-f79dfd8d8ddd) of the Java-based Spring-Security-SAML
 * saml2-js 
   ([GitHub](https://github.com/Clever/saml2), [npm](https://www.npmjs.com/package/saml2-js)) - 
   CoffeeScript implementation from [Clever](https://www.clever.com)

Note that these do not have HTTP Artifact Binding at time of writing, 
but would probably accept pull requests

## Contributing

We welcome contributions to code open-sourced by the Government Technology
Agency of Singapore. All contributors will be asked to sign a Contributor
License Agreement (CLA) in order to ensure that everybody is free to use their
contributions.
