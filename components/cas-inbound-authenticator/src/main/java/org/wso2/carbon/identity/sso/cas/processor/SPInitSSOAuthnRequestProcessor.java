/*
 *  Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.sso.cas.processor;

import org.wso2.carbon.identity.application.authentication.framework.cache.AuthenticationRequestCacheEntry;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.*;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationRequest;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.sso.cas.constants.CASSSOConstants;
import org.wso2.carbon.identity.sso.cas.context.CASMessageContext;
import org.wso2.carbon.identity.sso.cas.request.CASSpInitRequest;
import org.wso2.carbon.registry.core.utils.UUIDGenerator;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

public class SPInitSSOAuthnRequestProcessor extends IdentityProcessor {

    private String relyingParty;
    @Override
    public String getName() {
        return CASSSOConstants.CAS_SSO;
    }

    @Override
    public int getPriority() {
        return CASSSOConstants.SP_INIT_PROCESSOR_PRIORITY;
    }

    @Override
    public String getCallbackPath(IdentityMessageContext context) {
        return IdentityUtil.getServerURL(CASSSOConstants.IDENTITY, false, false);
    }

    @Override
    public String getRelyingPartyId() {
        return this.relyingParty;
    }

    @Override
    public boolean canHandle(IdentityRequest identityRequest) {
        if (identityRequest instanceof CASSpInitRequest && ((CASSpInitRequest) identityRequest).getServiceRequest
                () != null) {
            return true;
        }
        return false;
    }

    @Override
    protected FrameworkLoginResponse.FrameworkLoginResponseBuilder buildResponseForFrameworkLogin(IdentityMessageContext context) {
        IdentityRequest identityRequest = context.getRequest();
        Map parameterMap = identityRequest.getParameterMap();
        AuthenticationRequest authenticationRequest = new AuthenticationRequest();
        authenticationRequest.appendRequestQueryParams(parameterMap);
        Iterator authRequest = identityRequest.getHeaderMap().keySet().iterator();

        while (authRequest.hasNext()) {
            Object sessionDataKey = authRequest.next();
            authenticationRequest.addHeader((String) sessionDataKey, (String) identityRequest.getHeaderMap().get(sessionDataKey));
            authenticationRequest.getType();
        }
        authenticationRequest.setRelyingParty(getRelyingPartyId());
        authenticationRequest.setType(this.getName());
        authenticationRequest.setPassiveAuth(Boolean.parseBoolean(String.valueOf(context.getParameter("passiveAuth"))));
        authenticationRequest.setForceAuth(Boolean.parseBoolean(String.valueOf(context.getParameter("forceAuth"))));

        try {
            authenticationRequest.setCommonAuthCallerPath(URLEncoder.encode(this.getCallbackPath(context),
                    StandardCharsets.UTF_8.name()));
        } catch (UnsupportedEncodingException var9) {
            throw FrameworkRuntimeException.error("Error occurred while URL encoding callback path " +
                    this.getCallbackPath(context), var9);
        }

        AuthenticationRequestCacheEntry authRequest1 = new AuthenticationRequestCacheEntry(authenticationRequest);
        String sessionDataKey1 = UUIDGenerator.generateUUID();
        FrameworkUtils.addAuthenticationRequestToCache(sessionDataKey1, authRequest1);
        InboundUtil.addContextToCache(sessionDataKey1, context);
        FrameworkLoginResponse.FrameworkLoginResponseBuilder responseBuilder = new FrameworkLoginResponse.
                FrameworkLoginResponseBuilder(context);
        responseBuilder.setAuthName(this.getName());
        responseBuilder.setContextKey(sessionDataKey1);
        responseBuilder.setCallbackPath(this.getCallbackPath(context));
        responseBuilder.setRelyingParty(getRelyingPartyId());
        responseBuilder.setAuthType(this.getName());
        String commonAuthURL = IdentityUtil.getServerURL("commonauth", true, true);
        responseBuilder.setRedirectURL(commonAuthURL);
        return responseBuilder;
    }

    @Override
    public FrameworkLoginResponse.FrameworkLoginResponseBuilder process(IdentityRequest identityRequest) throws
            FrameworkException {
        CASMessageContext messageContext = new CASMessageContext((CASSpInitRequest) identityRequest, new
                HashMap<String, String>());
        this.relyingParty = messageContext.getServiceURL();
        return buildResponseForFrameworkLogin(messageContext);
    }
}