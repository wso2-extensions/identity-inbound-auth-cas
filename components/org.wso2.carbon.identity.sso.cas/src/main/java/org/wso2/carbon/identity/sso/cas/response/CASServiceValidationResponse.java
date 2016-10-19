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
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.sso.cas.constants.CASErrorConstants;
import org.wso2.carbon.identity.sso.cas.constants.CASSSOConstants;
import org.wso2.carbon.identity.sso.cas.context.CASMessageContext;
import org.wso2.carbon.identity.sso.cas.request.CASServiceValidateRequest;
import org.wso2.carbon.identity.sso.cas.ticket.ServiceTicket;
import org.wso2.carbon.identity.sso.cas.util.CASResourceReader;
import org.wso2.carbon.identity.sso.cas.util.CASSSOUtil;

public class CASServiceValidationResponse extends CASResponse {

    private String responseXml;
    private String redirectUrl;

    protected CASServiceValidationResponse(IdentityResponse.IdentityResponseBuilder builder) {
        super(builder);
        this.responseXml = ((CASServiceValidationResponseBuilder) builder).responseXml;
        this.redirectUrl = ((CASServiceValidationResponseBuilder) builder).redirectUrl;
    }

    public String getResponseString() {
        return responseXml;
    }

    public String getRedirectUrl() {
        return redirectUrl;
    }

    public CASMessageContext getContext() {
        return (CASMessageContext) this.context;
    }

    public static class CASServiceValidationResponseBuilder extends CASResponseBuilder {
        private String responseXml;
        private String redirectUrl;
        private static Log log = LogFactory.getLog(CASServiceValidationResponseBuilder.class);

        public CASServiceValidationResponseBuilder(IdentityMessageContext context) {
            super(context);
        }

        public CASServiceValidationResponse build() {
            return new CASServiceValidationResponse(this);
        }

        public CASServiceValidationResponseBuilder setRedirectUrl(String redirectUrl) {
            this.redirectUrl = redirectUrl;
            return this;
        }

        public String buildResponse() {
            CASMessageContext messageContext = (CASMessageContext) this.context;
            CASServiceValidateRequest req = messageContext.getValidateRequest();
            try {
                log.debug("CAS " + req.getRequestURI() + " query string: " + req.getQueryString());
                String serviceProviderUrl = req.getParameter(CASSSOConstants.SERVICE_PROVIDER_ARGUMENT);
                String serviceTicketId = req.getParameter(CASSSOConstants.SERVICE_TICKET_ARGUMENT);
                if (serviceProviderUrl == null || serviceProviderUrl.trim().length() == 0 || serviceTicketId == null
                        || serviceTicketId.trim().length() == 0) {
                    responseXml = CASSSOUtil.buildFailureResponse(CASErrorConstants.INVALID_REQUEST_CODE,
                            CASResourceReader.getInstance().getLocalizedString(
                                    CASErrorConstants.INVALID_REQUEST_MESSAGE, req.getLocale()));
                    return responseXml;
                }
                if (CASSSOUtil.isValidServiceTicket(serviceTicketId)) {
                    // "service" URL argument must match a valid service provider URL
                    if (!CASSSOUtil.isValidServiceProviderForServiceTicket(serviceTicketId)) {
                        responseXml = CASSSOUtil.buildFailureResponse(CASErrorConstants.INVALID_SERVICE_CODE, String.format(
                                CASResourceReader.getInstance().getLocalizedString(
                                        CASErrorConstants.INVALID_SERVICE_MESSAGE,
                                        req.getLocale()), serviceProviderUrl));
                    } else {
                        ServiceTicket serviceTicket = CASSSOUtil.consumeServiceTicket(serviceTicketId);
                        ServiceProvider serviceProvider = serviceTicket.getService();
                        ClaimMapping[] claimMapping = serviceProvider.getClaimConfig().getClaimMappings();
                        String principal = serviceTicket.getParentTicket().getPrincipal();
                        String attributesXml = CASSSOUtil.buildAttributesXml(principal, claimMapping);
                        responseXml = CASSSOUtil.buildSuccessResponse(principal, attributesXml);
                    }
                } else {
                    responseXml = CASSSOUtil.buildFailureResponse(CASErrorConstants.INVALID_TICKET_CODE,
                            String.format(CASResourceReader.getInstance().getLocalizedString(
                                    CASErrorConstants.INVALID_TICKET_MESSAGE, req.getLocale()), serviceTicketId));
                }
            } catch (IdentityException ex) {
                log.error("CAS serviceValidate internal error", ex);
                responseXml = CASSSOUtil.buildFailureResponse(CASErrorConstants.INTERNAL_ERROR_CODE,
                        CASResourceReader.getInstance().getLocalizedString(
                                CASErrorConstants.INTERNAL_ERROR_MESSAGE, req.getLocale()));
            }
            log.debug("CAS " + req.getRequestURI() + " response XML: " + responseXml);
            return responseXml;
        }
    }
}

