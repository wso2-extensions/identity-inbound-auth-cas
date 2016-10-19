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

package org.wso2.carbon.identity.sso.cas.request;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkClientException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityRequestFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.sso.cas.constants.CASSSOConstants;
import org.wso2.carbon.identity.sso.cas.exception.CAS2ClientException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class CASIdentityRequestFactory extends HttpIdentityRequestFactory {

    private static Log log = LogFactory.getLog(CASIdentityRequestFactory.class);

    @Override
    public String getName() {
        return "CASIdentityRequestFactory";
    }

    @Override
    public boolean canHandle(HttpServletRequest request, HttpServletResponse response) {
        String serviceProviderUrl = request.getParameter(CASSSOConstants.SERVICE_PROVIDER_ARGUMENT);
        String ticket = request.getParameter(CASSSOConstants.SERVICE_TICKET_ARGUMENT);
        return StringUtils.isNotBlank(serviceProviderUrl) || StringUtils.isNotBlank(ticket);
    }

    @Override
    public int getPriority() {
        return -3;
    }

    @Override
    public IdentityRequest.IdentityRequestBuilder create(HttpServletRequest request,
                                                         HttpServletResponse response) throws CAS2ClientException {
        String serviceProviderUrl = request.getParameter(CASSSOConstants.SERVICE_PROVIDER_ARGUMENT);
        String ticket = request.getParameter(CASSSOConstants.SERVICE_TICKET_ARGUMENT);
        CASIdentityRequest.CASIdentityRequestBuilder builder;
        try {
            if (!StringUtils.isEmpty(serviceProviderUrl) && StringUtils.isEmpty(ticket)) {
                builder = new CASSpInitRequest.CASSpInitRequestBuilder(request, response);
            } else {
                //TODO check another check if one of these param missing
                builder = new CASServiceValidateRequest.CASServiceValidateRequestBuilder(request, response);
                ((CASServiceValidateRequest.CASServiceValidateRequestBuilder) builder).setLocale(request);
            }
            super.create(builder, request, response);
        } catch (FrameworkClientException e) {
            throw CAS2ClientException.error("Error occurred while creating the Identity Request", e);
        }
        return builder;
    }
}
