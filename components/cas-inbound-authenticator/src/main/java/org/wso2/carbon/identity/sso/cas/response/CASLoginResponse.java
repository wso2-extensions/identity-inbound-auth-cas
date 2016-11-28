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
import org.wso2.carbon.identity.sso.cas.context.CASMessageContext;

import javax.servlet.http.Cookie;

/**
 * To build the CAS login response.
 */
public class CASLoginResponse extends CASResponse {

    private String redirectUrl;
    private Cookie casCookie;
    private String serviceTicketId;

    protected CASLoginResponse(IdentityResponse.IdentityResponseBuilder builder) {
        super(builder);
        this.redirectUrl = ((CASLoginResponseBuilder) builder).redirectUrl;
        this.casCookie = ((CASLoginResponseBuilder) builder).casCookie;
        this.serviceTicketId = ((CASLoginResponseBuilder) builder).serviceTicketId;
    }

    /**
     * Get the casCookie.
     * @return the casCookie
     */
    public Cookie getCasCookie() {
        return casCookie;
    }

    /**
     * Get the serviceTicketId
     * @return the serviceTicketId
     */
    public String getServiceTicketId() {
        return serviceTicketId;
    }

    /**
     * Get the redirectUrl.
     * @return the redirectUrl
     */
    public String getRedirectUrl() {
        return redirectUrl;
    }

    /**
     * Get the context.
     * @return context
     */
    public CASMessageContext getContext() {
        return (CASMessageContext) this.context;
    }

    /**
     * Inner class for build the CAS login response.
     */
    public static class CASLoginResponseBuilder extends CASResponseBuilder {

        private static Log log = LogFactory.getLog(CASLoginResponseBuilder.class);

        private String redirectUrl;
        private Cookie casCookie;
        private String serviceTicketId;

        public CASLoginResponseBuilder(IdentityMessageContext context) {
            super(context);
        }

        public CASLoginResponse build() {
            return new CASLoginResponse(this);
        }

        /**
         * Set the serviceTicketId.
         * @param serviceTicketId the serviceTicketId
         * @return serviceTicketId
         */
        public CASLoginResponseBuilder setServiceTicketId(String serviceTicketId) {
            this.serviceTicketId = serviceTicketId;
            return this;
        }

        /**
         * Set the cookie.
         * @param cookie the cookie.
         * @return cookie.
         */
        public CASLoginResponseBuilder setCasCookie(Cookie cookie) {
            this.casCookie = cookie;
            return this;
        }

        /**
         * Set the redirectUrl.
         * @param redirectUrl the redirectUrl
         * @return redirectUrl
         */
        public CASLoginResponseBuilder setRedirectUrl(String redirectUrl) {
            this.redirectUrl = redirectUrl;
            return this;
        }
    }
}