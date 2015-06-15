# OpenId Connect for Liferay

[![Travis](http://img.shields.io/travis/fmarco76/OpenIdConnectLiferay/master.png)](https://travis-ci.org/fmarco76/OpenIdConnectLiferay)

OpenId Connect for Liferay is a very rough but effective implementation of the
OpenId connect protocol for Liferay. Using this class it is possible to authenticate
with any OpenId proider specified in the code.

*Note: this code is a proof of concept and in the future the code for OpenId connect will
be integrated in the portlet [federated-login-ext](https://github.com/csgf/federated-login-ext)
which already includes SAML based protocols. The advantage is that the portlet
will provide a configuration panel where the provider and other useful information
can be configured.*


## Installation

Liferay is already installed and executing properly.

Edit the file `src/main/java/it/infn/ct/security/liferay/openidconnect/utils/Authenticator.java` modifying
the client-id, the secret and the callback using the information provided by the OpenId Connect server you
want to use.

Create the package with [maven](https://maven.apache.org) executing the command:

    $ mvn clean install
 
Maven will create two jar files Inside the directory `target`, copy `OpenIdConnectLiferay-0.1-jar-with-dependencies.jar`
inside the lib directory of Liferay (locate Liferay inside your application server, this will
contain the directory `WEB-INF/lib` where copy the jar).

Edit the Liferay file portal-ext.properties (if you have not create a new one in `WEB-INF/classes`) and add the
new AutoLogin class:

    auto.login.hooks=it.infn.ct.security.liferay.openidconnect.OpenIdConnectAutoLogin,com.liferay.portal.security.auth.CASAutoLogin,com.liferay.portal.security.auth.FacebookAutoLogin,com.liferay.portal.security.auth.NtlmAutoLogin,com.liferay.portal.security.auth.OpenIdAutoLogin,com.liferay.portal.security.auth.OpenSSOAutoLogin,com.liferay.portal.security.auth.RememberMeAutoLogin,com.liferay.portal.security.auth.SiteMinderAutoLogin

Finally, edit the sign-in link in your theme in order to redirect the user to the URL:

    /c/portal/login?openIdLogin=true

This allow to authente users using the sign-in link in the page. If you access a protected
page or open the login portlet the login form still is available. It is suggested to disable the
portlet if you plan to use only OpenId Connect.