# OPENID CONNECT FOR LIFERAY

## About

OpenId Connect for Liferay is a very rough but effective implementation of the
OpenId connect protocol for Liferay. Using this class it is possible to
authenticate with any OpenId proider specified in the code.

## Installation

Before to start you must have a Liferay instance already deployed and executing
properly.

Edit the file

    src/main/java/it/infn/ct/security/liferay/openidconnect/utils/Authenticator.java

to modify the client-id, the secret and the callback using the information
provided by the OpenId Connect server you want to use. The other values
reference to the *[EGI access portal authentication
service](https://access.egi.eu)*. If you plan to use a different *OpenID Connect
provider* the urls to the service need to be modified with the values provided
by your provider (this version does not use service description so all the urls
should be modified).

Create the package with [maven](https://maven.apache.org) executing the command:

    $ mvn clean install

Maven will create two jar files Inside the directory `target`, one including
all dependencies (with *with-depencies* suffix) and the other without. Copy the
one with dependencies inside the lib directory of Liferay (locate Liferay inside
your application server, this will contain the directory `WEB-INF/lib` where
copy the jar).

Edit the Liferay file portal-ext.properties (if you have not create a new one in
`WEB-INF/classes`) and add the new AutoLogin class:

    auto.login.hooks=\
      it.infn.ct.security.liferay.openidconnect.OpenIdConnectAutoLogin,\
      com.liferay.portal.security.auth.CASAutoLogin,\
      com.liferay.portal.security.auth.FacebookAutoLogin,\
      com.liferay.portal.security.auth.NtlmAutoLogin,\
      com.liferay.portal.security.auth.OpenIdAutoLogin,\
      com.liferay.portal.security.auth.OpenSSOAutoLogin,\
      com.liferay.portal.security.auth.RememberMeAutoLogin,\
      com.liferay.portal.security.auth.SiteMinderAutoLogin

Finally, edit the sign-in link in your theme in order to redirect the user to
the URL:

    /c/portal/login?openIdLogin=true

This allow to authente users using the sign-in link in the page. If you access a
protected page or open the login portlet the login form still is available. It
is suggested to disable the portlet if you plan to use only OpenId Connect.


## Usage

Users have to sign-in to the portal using the provided link *Sign-in* as
explained in the section [Installation](#installation). The only difference is
that the other sign-in procedure must be disabled so the user cannot see the
login for sh/she is used to.

## Contributors

* [Marco Fargetta](https://github.com/fmarco76/)

### Contribution

A revised version of this repository will be merged with the
[federated-login-ext repository](https://github.com/csgf/federated-login-ext)
therefore new contribution should go to that.
