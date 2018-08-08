# spcp-auth-client

A node.js library for SingPass and CorpPass, common authentication methods
for public-facing government systems in Singapore

## Quick Start

```javascript
const SPCPAuthClient = require('spcp-auth-client')

const client = new SPCPAuthClient({
  partnerEntityId: '<your partner entity id>',
  idpLoginURL: '<the SingPass/CorpPass IDP url to redirect login attempts to>',
  idpEndpoint: '<the SingPass/CorpPass IDP url for out-of-band (OOB) authentication>',
  esrvcID: '<the e-service identifier registered with SingPass/CorpPass>',
  appCert: '<the e-service public certificate issued to SingPass/CorpPass>',
  appKey: '<the e-service certificate private key>',
  spcpCert: '<the public certificate of SingPass/CorpPass, for OOB authentication>',
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

## Contributing

We welcome contributions to code open-sourced by the Government Technology
Agency of Singapore. All contributors will be asked to sign a Contributor
License Agreement (CLA) in order to ensure that everybody is free to use their
contributions.
