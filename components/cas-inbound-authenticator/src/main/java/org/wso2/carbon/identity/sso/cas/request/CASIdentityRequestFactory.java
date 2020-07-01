/*
 *  Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.sso.cas.request;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkClientException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityRequestFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponse;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.sso.cas.constants.CASConstants;
import org.wso2.carbon.identity.sso.cas.exception.CAS2ClientException;
import org.wso2.carbon.identity.sso.cas.util.CASResourceReader;
import org.wso2.carbon.identity.sso.cas.util.CASSSOUtil;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

public class CASIdentityRequestFactory extends HttpIdentityRequestFactory {

    private static final Log log = LogFactory.getLog(CASIdentityRequestFactory.class);

    @Override
    public String getName() {
        return "CASIdentityRequestFactory";
    }

    @Override
    public boolean canHandle(HttpServletRequest request, HttpServletResponse response) {

        String serviceProviderUrl = request.getParameter(CASConstants.CASSSOConstants.SERVICE_PROVIDER_ARGUMENT);
        String ticket = request.getParameter(CASConstants.CASSSOConstants.SERVICE_TICKET_ARGUMENT);
        boolean logout = request.getRequestURI().contains(CASConstants.CAS_LOGOUT_URI);
        return StringUtils.isNotBlank(serviceProviderUrl) || StringUtils.isNotBlank(ticket) || logout;
    }

    @Override
    public int getPriority() {
        return -3;
    }

    @Override
    public IdentityRequest.IdentityRequestBuilder create(HttpServletRequest request,
                                                         HttpServletResponse response) throws FrameworkClientException {

        boolean logout = request.getRequestURI().contains(CASConstants.CAS_LOGOUT_URI);
        String serviceProviderUrl = request.getParameter(CASConstants.CASSSOConstants.SERVICE_PROVIDER_ARGUMENT);
        String ticket = request.getParameter(CASConstants.CASSSOConstants.SERVICE_TICKET_ARGUMENT);
        CASIdentityRequest.CASIdentityRequestBuilder builder;
        if (logout) {
            builder = new CASLogoutRequest.CASSpInitRequestBuilder(request, response);
        }
        else if (StringUtils.isNotEmpty(serviceProviderUrl)) {
            if (StringUtils.isEmpty(ticket)) {
                builder = new CASSInitRequest.CASSpInitRequestBuilder(request, response);
            } else {
                builder = new CASServiceValidateRequest.CASServiceValidateRequestBuilder(request, response);
                ((CASServiceValidateRequest.CASServiceValidateRequestBuilder) builder).setLocale(request);
            }
        } else {
            throw CAS2ClientException.error("Invalid request message or invalid service url");
        }

        super.create(builder, request, response);
        return builder;
    }

    @Override
    public HttpIdentityResponse.HttpIdentityResponseBuilder handleException(FrameworkClientException exception,
                                                                            HttpServletRequest request,
                                                                            HttpServletResponse response) {
        String errorResponse;
        HttpIdentityResponse.HttpIdentityResponseBuilder builder = new HttpIdentityResponse
                .HttpIdentityResponseBuilder();
        if (((CAS2ClientException) exception).getAcsUrl() != null) {
            try {
                Map<String, String[]> queryParams = new HashMap();
                String genericErrorPage = IdentityUtil
                        .getServerURL(CASConstants.CASSSOConstants.NOTIFICATION_ENDPOINT, false, false);
                queryParams.put(CASConstants.CASSSOConstants.STATUS,
                        new String[] { URLEncoder.encode(((CAS2ClientException)
                        exception).getExceptionStatus(), StandardCharsets.UTF_8.name())});
                queryParams.put(CASConstants.CASSSOConstants.STATUS_MSG,
                        new String[] { URLEncoder.encode(((CAS2ClientException)
                        exception).getExceptionMessage(), StandardCharsets.UTF_8.name())});
                builder.setParameters(queryParams);
                builder.setRedirectURL(genericErrorPage);
                builder.setStatusCode(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
            } catch (UnsupportedEncodingException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Error while encoding query parameters.", e);
                }
            }
        } else {
            String redirectURL = request.getParameter(CASConstants.CASSSOConstants.SERVICE_PROVIDER_ARGUMENT);
            if (((CAS2ClientException) exception).getServiceTicketId() != null) {
                errorResponse = CASSSOUtil.buildFailureResponse(CASConstants.CASErrorConstants.INVALID_TICKET_CODE,
                        String.format(CASResourceReader.getInstance().getLocalizedString(
                                        CASConstants.CASErrorConstants.INVALID_TICKET_MESSAGE, request.getLocale()),
                                ((CAS2ClientException) exception).getServiceTicketId()));
            } else {
                errorResponse = CASSSOUtil.buildFailureResponse(CASConstants.CASErrorConstants.INVALID_REQUEST_CODE,
                        CASResourceReader.getInstance().getLocalizedString(
                                CASConstants.CASErrorConstants.INVALID_REQUEST_MESSAGE, request.getLocale()));
            }
            builder.setBody(errorResponse);
            builder.setRedirectURL(redirectURL);
            builder.setStatusCode(HttpServletResponse.SC_BAD_REQUEST);
        }
        return builder;
    }
}
