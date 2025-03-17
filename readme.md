# OAuth2 authorization server

This is a Spring Boot-based OAuth2 authorization server for demonstration purpose. This server supports
Client Credentials flow using Client Assertion authentication.
In this application, we provided the following beans:

* `com.bondtech.configuration.AuthServerConfig.authorizationServerSecurityFilterChain` This bean is 
the SecurityFilterChain carrying standard security configuration for OAuth2 Authorization 
Server.
* `authorizationServerSettings` This bean is purely for demonstration purpose that we can customize the path to the
different OAuth2 endpoints exposed by the authorization server.
*  `registeredClientRepository` This bean prepares a single registered OAuth2 client. In a real-world OAuth2 
authorization server, all the details of the clients can be stored in a database and used to create RegisteredClients to
be stored in `registeredClientRepository`
* `jwkSource` This bean provides the keystore used by the OAuth2 authorization server to use the private key for signing
the access_token and provide the public keys in the keystore to OAuth2 resource server for validating the access_token.

In this application, we simplified the setup by using the same jwks endpoint for the public keys used in
validating both client_assertion and access_token i.e. `.jwkSetUrl("http://localhost:8282/oauth2/jwks")` 
`.jwkSetEndpoint("/oauth2/jwks")` and In a real-world scenario, there should be a dedicated endpoint for
the public keys used for validating client_assertion or customized client authentication logic to use a local keystore
in validation.

## Authorization Server
To bring up the **authorization server**, we  need the environment variables `key_alias`, `key_password`, `keystore_password` and 
`keystore_path`. The main class is `com.bondtech.AuthServerApplication`.

## Util class

We have the class `com.bondtech.Util` to generate a client_assertion to be used in the request sent to our authorization
server for access token. The environment variables required are, again, `key_alias`, `key_password`, `keystore_password` and 
`keystore_path`.

The curl command example:
`curl -X POST http://localhost:8282/oauth2/token -H "Content-Type: application/x-www-form-urlencoded" -d "grant_type=client_credentials" -d "client_id=client-id" -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" -d "client_assertion=eyJraWQiOiJib25kdGVjaC5jb20iLCJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJjbGllbnQtaWQiLCJzdWIiOiJjbGllbnQtaWQiLCJhdWQiOiJodHRwOi8vbG9jYWxob3N0OjgyODIvb2F1dGgyL3Rva2VuIiwiZXhwIjoxNzQyMTU3OTc5LCJpYXQiOjE3NDIxNTQ5NzksImp0aSI6ImM2YmIxOWE3LWZmMWEtNDI2NS1iMjdhLWYzNTA0ZWQ4ZGFlNyJ9.b8MRBV46rOAGWpOHWg0F2fbI3BILExCYyaFBwv2z395rWFFTRVjZUWnlsl8JfJ2mUFdxL8ooI-eFf4GCKC9zMDZvcesm-kJvQ3ry1h3n8EOVcMIImtpx9k2NMGcdlW6Ejx849SxvpjVLFOyYKylwxZuQ4o5u4cDwwCWSmOQi_bMcWuR4UDcbExODdXpAGlo10A0HMEOC6SuK3NK9Cx1OLYiWaEkEoAA3NN8LpWg2cB8belkn5p3W5coZ_hvrqk_XvE9p-ydmaVTwYxbXJIk9K8ROTPoFW747p1EvFGwp0Lhl8sUOV4CsmzZBn62tsCahw2cMLQNkUJpjwmoNu9n2cg"`


## Client Credentials Flow using Client Assertion for authentication
<img src="https://github.com/user-attachments/assets/672cc4e8-ca85-42bb-b7a4-ca1d747d4647" width="700"/>

<!-- original raw code after pasting the image
![image](https://github.com/user-attachments/assets/298d033d-e2b4-4d00-bddc-c7caf44109d0)
-->

