/**
 * *********************************************************************
 * Copyright (c) 2011: Istituto Nazionale di Fisica Nucleare (INFN), Italy
 * Consorzio COMETA (COMETA), Italy
 *
 * See http://www.infn.it and and http://www.consorzio-cometa.it for details on
 * the copyright holders.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 **********************************************************************
 */
package it.infn.ct.security.liferay.openidconnect.utils;

import com.liferay.portal.kernel.log.Log;
import com.liferay.portal.kernel.log.LogFactoryUtil;
import com.liferay.portal.security.auth.AuthException;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponseParser;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCAccessTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import com.nimbusds.openid.connect.sdk.UserInfoErrorResponse;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoResponse;
import com.nimbusds.openid.connect.sdk.UserInfoSuccessResponse;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.servlet.http.HttpServletRequest;

/**
 *
 * @author Marco Fargetta <marco.fargetta@ct.infn.it>
 */
public class Authenticator {
    static {
        disableSslVerification();
    }

    private static void disableSslVerification() {
        try {
            // Create a trust manager that does not validate certificate chains
            TrustManager[] trustAllCerts = new TrustManager[]{new X509TrustManager() {
                public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                    return null;
                }
                public void checkClientTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {
                }

                public void checkServerTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {
                }
            }
            };

            // Install the all-trusting trust manager
            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

            // Create all-trusting host name verifier
            HostnameVerifier allHostsValid = new HostnameVerifier() {
                public boolean verify(String arg0, SSLSession arg1) {
                    return true;
                }
            };

            // Install the all-trusting host verifier
            HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);
        } catch (NoSuchAlgorithmException e) {
        } catch (KeyManagementException e) {
        }
    }

    private ClientAuthentication authC= null;
    private URI callback = null;
    private URI oauthS = null;
    private URI tokenS = null;
    private URI userS = null;
    private State state = null;
    private static final Log _log = LogFactoryUtil.getLog(Authenticator.class);

    public Authenticator(){
        this(new State());
    }
    
    public Authenticator(State state) {
        authC = new ClientSecretBasic(new ClientID("xxxxxxxxxxxxxx"), new Secret("xxxxxxxx"));
        this.state = state;
        try {
            callback = new URI("https://csgf.egi.eu/c/portal/login");
            oauthS = new URI("https://unity.egi.eu:2443/oauth2-as/oauth2-authz");
            tokenS = new URI("https://unity.egi.eu:2443/oauth2/token");
            userS = new URI("https://unity.egi.eu:2443/oauth2/userinfo");
        } catch (URISyntaxException ex) {
            _log.error(ex);
        }
    }

    public String getAuthRequestURL() {
        Nonce nonce = new Nonce();

        AuthenticationRequest req = new AuthenticationRequest(
                oauthS,
                new ResponseType(ResponseType.Value.CODE),
                Scope.parse("profile openid"),
                authC.getClientID(),
                callback,
                state,
                nonce);

        try {
            return req.toURI().toString();
        } catch (SerializeException ex) {
            _log.error(ex);
        }
        return null;
    }
    
    public UserInfo getUserInfo(HttpServletRequest request) throws AuthException{
        AuthenticationResponse resp = null;
        
        try {
            resp = AuthenticationResponseParser.parse(
                    new URI(request.getRequestURL().append("?").append(request.getQueryString()).toString())
            );
        } catch (ParseException ex) {
            _log.error(ex);
        } catch (URISyntaxException ex) {
            _log.error(ex);
        }
        
        if (resp==null || resp instanceof AuthenticationErrorResponse)
            throw new AuthException("OpenId Connect server does not authenticate");
        
        AuthenticationSuccessResponse succesResp = (AuthenticationSuccessResponse) resp;
        
        if(!verifyState(succesResp.getState()))
            throw new AuthException("OpenId Connect server does not authenticate");
        
        AuthorizationCode code = succesResp.getAuthorizationCode();
        
        TokenRequest tokenReq = new TokenRequest(
                tokenS,
                authC,
                new AuthorizationCodeGrant(code, callback)
        );
        HTTPResponse tokenHTTPResp = null;
        
        try {
            _log.debug("Token request header content: "+tokenReq.toHTTPRequest().getHeader("Content-Type"));
            _log.debug("Token request header authorisation: "+tokenReq.toHTTPRequest().getHeader("Authorization"));
            _log.debug("Token request query: "+tokenReq.toHTTPRequest().getQuery());
            tokenHTTPResp = tokenReq.toHTTPRequest().send();
        } catch (SerializeException ex) {
            _log.error(ex);
        } catch (IOException ex) {
            _log.error(ex);
        }
        
        TokenResponse tokenResp = null;
        try {
            _log.debug(tokenHTTPResp.getContent());
            tokenResp = OIDCTokenResponseParser.parse(tokenHTTPResp);
        } catch (ParseException ex) {
            _log.error(ex);
        }
        
        if(tokenResp == null || tokenResp instanceof TokenErrorResponse){
            throw new AuthException("OpenId Connect server does not authenticate");
        }
        OIDCAccessTokenResponse accessTokenResponse = (OIDCAccessTokenResponse) tokenResp;
        
        
        UserInfoRequest userInfoReq = new UserInfoRequest(
                userS,
                accessTokenResponse.getBearerAccessToken());
        
        
        HTTPResponse userInfoHTTPResp = null;
        try {
            userInfoHTTPResp = userInfoReq.toHTTPRequest().send();
        } catch (SerializeException ex) {
            _log.error(ex);
        } catch (IOException ex) {
            _log.error(ex);
        }
        
        UserInfoResponse userInfoResp = null;
        
        try {
            userInfoResp = UserInfoResponse.parse(userInfoHTTPResp);
        } catch (ParseException ex) {
            _log.error(ex);
        }

        if(userInfoResp==null || userInfoResp instanceof UserInfoErrorResponse)
            throw new AuthException("OpenId Connect server does not authenticate");

        UserInfoSuccessResponse successUserResponse = (UserInfoSuccessResponse) userInfoResp;
        
        return successUserResponse.getUserInfo();
    }

    public State getState() {
        return state;
    }

    private boolean verifyState(State state) {
        return state.getValue().equals(this.state.getValue());
    }

}
