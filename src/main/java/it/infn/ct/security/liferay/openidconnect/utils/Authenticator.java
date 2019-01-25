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
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.ReadOnlyJWTClaimsSet;
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
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
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
import com.nimbusds.openid.connect.sdk.util.DefaultJWTDecoder;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Date;
import java.util.Scanner;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.servlet.http.HttpServletRequest;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;

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
    private URI tokenCertSign = null;
    private State state = null;
    private String issuer = null;
    private String aud = null;
    private static final Log _log = LogFactoryUtil.getLog(Authenticator.class);

    public Authenticator(){
        this(new State());
    }

    public Authenticator(State state) {
        authC = new ClientSecretBasic(new ClientID("csgf"), new Secret("*************************************************"));
        this.state = state;
        try {
            callback = new URI("https://csgf.egi.eu/c/portal/login");
            oauthS = new URI("https://aai.egi.eu/oidc/authorize");
            tokenS = new URI("https://aai.egi.eu/oidc/token");
            userS = new URI("https://aai.egi.eu/oidc/userinfo");
            tokenCertSign = new URI("https://aai.egi.eu/oidc/jwk");
            issuer = "https://aai.egi.eu/oidc/";
            aud = "csgf";

        } catch (URISyntaxException ex) {
            _log.error(ex);
        }
    }

    public String getAuthRequestURL() {
        Nonce nonce = new Nonce();

        AuthenticationRequest req = new AuthenticationRequest(
                oauthS,
                new ResponseType(ResponseType.Value.CODE),
                Scope.parse("profile openid email eduperson_entitlement"),
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

    public UserInfo getUserInfo(HttpServletRequest request) throws AuthException {
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
            _log.debug("Token response: "+tokenHTTPResp.getContent());
            tokenResp = OIDCTokenResponseParser.parse(tokenHTTPResp);
        } catch (ParseException ex) {
            _log.error(ex);
        }

        if(tokenResp == null || tokenResp instanceof TokenErrorResponse){
            throw new AuthException("OpenId Connect server does not authenticate");
        }

        RSAPublicKey providerKey= null;

        JSONObject key;
        try {
            key = getProviderRSAKey(tokenCertSign.toURL().openStream());
            providerKey = RSAKey.parse(key).toRSAPublicKey();
        } catch (MalformedURLException ex) {
            _log.error(ex);
        } catch (IOException ex) {
            _log.error(ex);
        } catch (java.text.ParseException ex) {
            _log.error(ex);
        } catch (NoSuchAlgorithmException ex) {
            _log.error(ex);
        } catch (InvalidKeySpecException ex) {
            _log.error(ex);
        }

        OIDCAccessTokenResponse accessTokenResponse = (OIDCAccessTokenResponse) tokenResp;

        DefaultJWTDecoder jwtDec = new DefaultJWTDecoder();
        jwtDec.addJWSVerifier(new RSASSAVerifier(providerKey));
        ReadOnlyJWTClaimsSet claims=null;
        try {
            claims = jwtDec.decodeJWT(accessTokenResponse.getIDToken());
            _log.debug("Claims in ID Token: " + claims.toJSONObject().toJSONString());
        } catch (JOSEException ex) {
            _log.error(ex);
        } catch (java.text.ParseException ex) {
            _log.error(ex);
        }

        if(claims==null){
            throw new AuthException("Not able to decode the ID Token");
        }

        if(claims.getExpirationTime().before(new Date())){
            throw new AuthException("ID Token Expired");
        }

        if(! claims.getIssuer().equals(issuer)){
            throw new AuthException("ID Token issuer "+claims.getIssuer()+" does not match");
        }

        if(! claims.getAudience().contains(aud)){
            throw new AuthException("ID Token audience "+claims.getAudience()+" does not match");
        }
        _log.debug("Requesting user info");
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

        _log.debug("Get the user info response");
        try {
            userInfoResp = UserInfoResponse.parse(userInfoHTTPResp);
        } catch (ParseException ex) {
            _log.error(ex);
        }

        if(userInfoResp==null || userInfoResp instanceof UserInfoErrorResponse)
            throw new AuthException("OpenId Connect server does not authenticate");

        UserInfoSuccessResponse successUserResponse = (UserInfoSuccessResponse) userInfoResp;

        _log.debug("User info generated for: " + successUserResponse.getUserInfo().getEmail().toString());
        return successUserResponse.getUserInfo();
    }

    public State getState() {
        return state;
    }

    private boolean verifyState(State state) {
        return state.getValue().equals(this.state.getValue());
    }

    private JSONObject getProviderRSAKey(InputStream is){
        StringBuilder sb = new StringBuilder();
        Scanner scanner = new Scanner(is);
        while(scanner.hasNext()){
           sb.append(scanner.next());
        }

        String jString = sb.toString();

        try {
            JSONObject json = JSONObjectUtils.parse(jString);
            JSONArray keyList = (JSONArray) json.get("keys");

            for(Object key: keyList){
                JSONObject obj = (JSONObject) key;
                if(obj.get("kty").equals("RSA")){
                    return obj;
                }
            }
        } catch (ParseException ex) {
            _log.error(ex);
        }

        return null;
    }

}
