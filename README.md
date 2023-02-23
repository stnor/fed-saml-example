# Example application for federated SAML using Spring SAML2

## Goals
* Work in a large federation with the central metadata containing 200 IdP and 50+ SP:s
* Backwards compatible URL-mapping with the legacy Spring SAML extension project
    * http://127.0.0.1:8080/saml/login <-- Redirect to /start/login/saml for idp selection (not part of this project atm)
    * http://127.0.0.1:8080/saml/login?idp=entityId <-- can be url, see metadata, unknown RP should redirect to /start/login/saml for idp selection
    * http://127.0.0.1:8080/saml/SSO for assertions
    * http://127.0.0.1:8080/saml/SingleSignout for single-signout
 
## Outstanding issues
* Verify the metadata XML signature?

