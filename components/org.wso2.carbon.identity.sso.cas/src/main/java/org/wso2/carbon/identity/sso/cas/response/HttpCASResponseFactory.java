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

package org.wso2.carbon.identity.sso.cas.response;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponse;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponseFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;
import org.wso2.carbon.identity.sso.cas.constants.CASSSOConstants;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;

public class HttpCASResponseFactory extends HttpIdentityResponseFactory {

    private static Log log = LogFactory.getLog(HttpCASResponseFactory.class);

    @Override
    public String getName() {
        return "HttpCASResponseFactory";
    }

    @Override
    public boolean canHandle(IdentityResponse identityResponse) {
        if (identityResponse instanceof CASLoginResponse || identityResponse instanceof CASErrorResponse ||
                identityResponse instanceof CASServiceValidationResponse) {
            return true;
        }
        return false;
    }

    @Override
    public HttpIdentityResponse.HttpIdentityResponseBuilder create(IdentityResponse identityResponse) {

        if (identityResponse instanceof CASLoginResponse) {
            return sendResponse(identityResponse);
        } else {
            return sendServiceValidationResponse(identityResponse);
        }
    }

    @Override
    public HttpIdentityResponse.HttpIdentityResponseBuilder create(HttpIdentityResponse.HttpIdentityResponseBuilder
                                                                           httpIdentityResponseBuilder, IdentityResponse
                                                                           identityResponse) {
        return create(identityResponse);
    }

    private HttpIdentityResponse.HttpIdentityResponseBuilder sendResponse(IdentityResponse identityResponse) {
        CASLoginResponse loginResponse = ((CASLoginResponse) identityResponse);
        HttpIdentityResponse.HttpIdentityResponseBuilder builder = new HttpIdentityResponse
                .HttpIdentityResponseBuilder();
        Cookie cookie = loginResponse.getCasCookie();
        String serviceTicketId = loginResponse.getServiceTicketId();
        String redirectUrl = loginResponse.getRedirectUrl();
        Map<String, String[]> queryParams = new HashMap();
        queryParams.put(CASSSOConstants.SERVICE_TICKET_ARGUMENT, new String[]{serviceTicketId});
        builder.addCookie(cookie);
        builder.setParameters(queryParams);
        builder.setRedirectURL(redirectUrl);
        builder.setStatusCode(HttpServletResponse.SC_MOVED_TEMPORARILY);
        return builder;
    }

    private HttpIdentityResponse.HttpIdentityResponseBuilder sendServiceValidationResponse(IdentityResponse identityResponse) {
        CASServiceValidationResponse casServiceValidationResponse = ((CASServiceValidationResponse) identityResponse);
        HttpIdentityResponse.HttpIdentityResponseBuilder builder = new HttpIdentityResponse
                .HttpIdentityResponseBuilder();
        String responseString = casServiceValidationResponse.getResponseString();
        String redirectUrl = casServiceValidationResponse.getRedirectUrl();
        builder.setBody(responseString);
        builder.setStatusCode(HttpServletResponse.SC_OK);
        builder.setRedirectURL(redirectUrl);
        return builder;
    }
}
