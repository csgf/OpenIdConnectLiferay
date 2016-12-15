/***********************************************************************
 *  Copyright (c) 2011: 
 *  Istituto Nazionale di Fisica Nucleare (INFN), Italy
 *  Consorzio COMETA (COMETA), Italy
 * 
 *  See http://www.infn.it and and http://www.consorzio-cometa.it for details on
 *  the copyright holders.
 * 
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 * 
 *  http://www.apache.org/licenses/LICENSE-2.0
 * 
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ***********************************************************************/

package it.infn.ct.security.liferay.openidconnect;

import com.liferay.portal.NoSuchUserException;
import com.liferay.portal.kernel.log.Log;
import com.liferay.portal.kernel.log.LogFactoryUtil;
import com.liferay.portal.kernel.util.StackTraceUtil;
import com.liferay.portal.kernel.util.StringPool;
import com.liferay.portal.model.User;
import com.liferay.portal.model.UserGroup;
import com.liferay.portal.security.auth.AuthException;
import com.liferay.portal.security.auth.AutoLogin;
import com.liferay.portal.security.auth.AutoLoginException;
import com.liferay.portal.service.UserGroupLocalServiceUtil;
import com.liferay.portal.service.UserLocalServiceUtil;
import com.liferay.portal.util.PortalUtil;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import it.infn.ct.security.liferay.openidconnect.utils.Authenticator;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Locale;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 *
 * @author Marco Fargetta <marco.fargetta@ct.infn.it>
 */
public class OpenIdConnectAutoLogin implements AutoLogin{

	private static final Log _log = LogFactoryUtil.getLog(OpenIdConnectAutoLogin.class);
	        
	@Override
	public String[] login(HttpServletRequest request, HttpServletResponse response)
			throws AutoLoginException {

            if(request.getParameter("openIdLogin")!=null &&
                    request.getParameter("openIdLogin").equalsIgnoreCase("true")){
                _log.debug("OpenID Connect auth request");
                Authenticator authZ = new Authenticator();

                try {
                    request.getSession().setAttribute("LOGIN", authZ.getState());
                    response.sendRedirect(authZ.getAuthRequestURL());
                    return null;
                } catch (IOException ex) {
                    _log.error(ex);
                }
            }
            
            _log.debug("Check if the session is for login: "+request.getSession().getAttribute("LOGIN"));
            if(request.getSession().getAttribute("LOGIN") != null){
                _log.debug("Remote Authentication performed. Retrieve the token");
                State state = (State) request.getSession().getAttribute("LOGIN");
                
/*
                Enumeration pNames= request.getParameterNames();
                while(pNames.hasMoreElements()){
                    String name= (String) pNames.nextElement();
                    _log.debug("Parameter "+name+"= "+request.getParameter(name));
                    
                }
*/                
                if(request.getParameter("error")!=null){
                    try {
                        response.sendRedirect("/not_authorised");
                        return null;
                    } catch (IOException ex) {
                        _log.error(ex);
                    }
                }
                
                if(request.getParameter("code")!=null &&
                        request.getParameter("state")!=null){
                    request.getSession().removeAttribute("LOGIN");
                    
                    Authenticator authZ = new Authenticator(state);
                    
                    UserInfo userInfo = null;
                    try {
                        userInfo = authZ.getUserInfo(request);
                        _log.debug("User Information: givenName='"+userInfo.getGivenName()+"' familyName='"+userInfo.getFamilyName()+
                                "' globalName='"+userInfo.getName()+"' hasActiveSla='"+userInfo.getClaim("hasActiveSla", String.class)+
                                "' confirmedRegistration='" +userInfo.getClaim("confirmedRegistration", String.class)+"'");
                        if(!userInfo.getClaim("hasActiveSla", String.class).equalsIgnoreCase("true") ||
                                !userInfo.getClaim("confirmedRegistration", String.class).equalsIgnoreCase("true")) {
                            try {
                                response.sendRedirect("/not_authorised");
                                return null;
                            } catch (IOException ex) {
                                _log.error(ex);
                            }                            
                        }
                        
                    } catch (AuthException ex) {
                        _log.error(ex);
                        return null;
                    }
                    
                    String[] credentials = null;
                    long companyId = 0;
                    
                    try {
                        companyId = PortalUtil.getCompany(request).getCompanyId();
                        
                        String mail = userInfo.getEmail().toString();
                        _log.info("Check the mail: "+mail);
                        
                        User user = null;
                        try{
                            user = UserLocalServiceUtil.getUserByEmailAddress(companyId, mail);
                        }
                        catch(NoSuchUserException ex){
                            
                            String givenName;
                            String familyName;
                            
                            if(userInfo.getGivenName()==null || userInfo.getGivenName().isEmpty()){
                                givenName = userInfo.getName();
                            }
                            else{
                                givenName = userInfo.getGivenName();
                            }
                            
                            if(givenName!=null && !givenName.isEmpty()){
                                if(userInfo.getFamilyName()!=null && !userInfo.getFamilyName().isEmpty()){
                                    familyName = userInfo.getFamilyName();
                                }
                                else{
                                    if(givenName.contains(" ")){
                                        String[] names= givenName.split(" ");
                                        givenName= "";
                                        for(int i=0; i<names.length-1; i++){
                                            givenName+=names[i];
                                            if(1<names.length-2)
                                                givenName+=" ";
                                        }
                                        familyName= names[names.length-1];
                                    }
                                    else{
                                        familyName= givenName;
                                    }
                                }
                            }
                            else{
                                givenName = "EGI";
                                familyName = "USER "+ (int)(10000*Math.random());
                            }
                                
                            _log.info("New user "+givenName+" "+familyName+" "+mail+" (id "+userInfo.getStringClaim("persistent")+")");
                            SecureRandom random = new SecureRandom();
                            String pass = new BigInteger(130, random).toString(32);
                            UserGroup uGroup = UserGroupLocalServiceUtil.getUserGroup(companyId, "UnityUser");
                            long [] userGroupIds = new long[1];
                            userGroupIds[0] = uGroup.getUserGroupId();
                            user = UserLocalServiceUtil.addUser(
                                    0, companyId, 
                                    true, null, null,
                                    false, userInfo.getStringClaim("persistent"), 
                                    mail, 
                                    0, userInfo.getStringClaim("persistent")+"_at_egi_unity", 
                                    Locale.ENGLISH, 
                                    givenName, StringPool.BLANK, familyName,
                                    0, 0, true, 
                                    1, 1, 1970, 
                                    StringPool.BLANK, null, 
                                    null, null, userGroupIds,
                                    false, null);

                            
                        }
                        credentials = new String[3];

                        credentials[0] = String.valueOf(user.getUserId());
                        credentials[1] = user.getPassword();
                        credentials[2] = Boolean.TRUE.toString();

                        return credentials;
                        
                        
                    }
                    catch (Exception e) {
                            _log.error(StackTraceUtil.getStackTrace(e));
                            throw new AutoLoginException(e);
                    }            
                }
            }
           return null;
	}

}
