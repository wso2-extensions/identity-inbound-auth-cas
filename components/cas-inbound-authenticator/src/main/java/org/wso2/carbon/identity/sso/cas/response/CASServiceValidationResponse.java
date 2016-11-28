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
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationResult;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.sso.cas.constants.CASErrorConstants;
import org.wso2.carbon.identity.sso.cas.constants.CASSSOConstants;
import org.wso2.carbon.identity.sso.cas.context.CASMessageContext;
import org.wso2.carbon.identity.sso.cas.exception.CAS2ClientException;
import org.wso2.carbon.identity.sso.cas.request.CASServiceValidateRequest;
import org.wso2.carbon.identity.sso.cas.ticket.ServiceTicket;
import org.wso2.carbon.identity.sso.cas.util.CASResourceReader;
import org.wso2.carbon.identity.sso.cas.util.CASSSOUtil;

/**
 * To build the CAS Service Validation Response.
 */
public class CASServiceValidationResponse extends CASResponse {

    private String responseXml;
    private String redirectUrl;

    protected CASServiceValidationResponse(IdentityResponse.IdentityResponseBuilder builder) {
        super(builder);
        this.responseXml = ((CASServiceValidationResponseBuilder) builder).responseXml;
        this.redirectUrl = ((CASServiceValidationResponseBuilder) builder).redirectUrl;
    }

    /**
     * Get the Response String.
     *
     * @return the responseXml
     */
    public String getResponseString() {
        return responseXml;
    }

    /**
     * Get the redirect url
     *
     * @return the redirectUrl
     */
    public String getRedirectUrl() {
        return redirectUrl;
    }

    /**
     * To get the context
     *
     * @return the CASMessageContext.
     */
    public CASMessageContext getContext() {
        return (CASMessageContext) this.context;
    }

    /**
     * Inner class for build the CAS service validation response.
     */
    public static class CASServiceValidationResponseBuilder extends CASResponseBuilder {
        private static Log log = LogFactory.getLog(CASServiceValidationResponseBuilder.class);
        private String responseXml;
        private String redirectUrl;

        public CASServiceValidationResponseBuilder(IdentityMessageContext context) {
            super(context);
        }

        public CASServiceValidationResponse build() {
            return new CASServiceValidationResponse(this);
        }

        /**
         * Set the redirect url.
         *
         * @param redirectUrl the redirectUrl
         * @return the redirectUrl
         */
        public CASServiceValidationResponseBuilder setRedirectUrl(String redirectUrl) {
            this.redirectUrl = redirectUrl;
            return this;
        }

        /**
         * build the response for validation request.
         *
         * @return the responseXml
         */
        public String buildResponse() {
            CASMessageContext messageContext = (CASMessageContext) this.context;
            CASServiceValidateRequest req = messageContext.getValidateRequest();
            try {
                if (log.isDebugEnabled()) {
                    log.debug("CAS " + req.getRequestURI() + " query string: " + req.getQueryString());
                }
                String serviceProviderUrl = req.getParameter(CASSSOConstants.SERVICE_PROVIDER_ARGUMENT);
                String serviceTicketId = req.getParameter(CASSSOConstants.SERVICE_TICKET_ARGUMENT);
                if (serviceProviderUrl == null || serviceProviderUrl.trim().length() == 0 || serviceTicketId == null
                        || serviceTicketId.trim().length() == 0) {
                    throw CAS2ClientException.error("Required request parameters were missing",
                            CASErrorConstants.INVALID_REQUEST_CODE, (CASResourceReader.getInstance().getLocalizedString(
                                    CASErrorConstants.INVALID_REQUEST_MESSAGE, req.getLocale())), null, null);
                }
                if (CASSSOUtil.isValidServiceTicket(serviceTicketId)) {
                    // "service" URL argument must match a valid service provider URL
                    if (!CASSSOUtil.isValidAcsUrlForServiceTicket(serviceProviderUrl, serviceTicketId)) {
                        throw CAS2ClientException.error("ServiceProviderUrl is not valid",
                                CASErrorConstants.INVALID_SERVICE_CODE, CASResourceReader.getInstance().getLocalizedString(
                                        CASErrorConstants.INVALID_SERVICE_MESSAGE, req.getLocale()), serviceProviderUrl, null);
                    } else {
                        ServiceTicket serviceTicket = CASSSOUtil.consumeServiceTicket(serviceTicketId);
                        AuthenticationResult authenticationResult = serviceTicket.getParentTicket().getAuthenticationResult();
                        ServiceProvider serviceProvider = CASSSOUtil.getServiceProviderByUrl(serviceProviderUrl,
                                String.valueOf(messageContext.getRequest().getTenantDomain()));
                        ClaimMapping[] claimMapping = serviceProvider.getClaimConfig().getClaimMappings();
                        String attributesXml = CASSSOUtil.buildAttributesXml(authenticationResult, claimMapping);
                        responseXml = CASSSOUtil.buildSuccessResponse(String.valueOf(authenticationResult.getSubject()),
                                attributesXml);
                    }
                } else
                    throw CAS2ClientException.error("ServiceTicket is not valid", CASErrorConstants.INVALID_TICKET_CODE,
                            (CASResourceReader.getInstance().getLocalizedString(
                                    CASErrorConstants.INVALID_TICKET_MESSAGE, req.getLocale())), null, serviceTicketId);
            } catch (IdentityException ex) {
                log.error("CAS serviceValidate internal error", ex);
                responseXml = CASSSOUtil.buildFailureResponse(CASErrorConstants.INTERNAL_ERROR_CODE,
                        CASResourceReader.getInstance().getLocalizedString(
                                CASErrorConstants.INTERNAL_ERROR_MESSAGE, req.getLocale()));
            }
            if (log.isDebugEnabled()) {
                log.debug("CAS " + req.getRequestURI() + " response XML: " + responseXml);
            }
            return responseXml;
        }
    }
}