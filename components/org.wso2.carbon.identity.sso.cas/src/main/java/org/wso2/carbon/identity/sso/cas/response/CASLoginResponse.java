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

public class CASLoginResponse extends CASResponse {

    private String respString;
    private String relayState;
    private String redirectUrl;
    private String subject;
    private String tenantDomain;
    private Cookie casCookie;
    private String serviceTicketId;

    protected CASLoginResponse(IdentityResponse.IdentityResponseBuilder builder) {
        super(builder);
        this.respString = ((CASLoginResponseBuilder) builder).respString;
        this.relayState = ((CASLoginResponseBuilder) builder).relayState;
        this.redirectUrl = ((CASLoginResponseBuilder) builder).redirectUrl;
        this.tenantDomain = ((CASLoginResponseBuilder) builder).tenantDomain;
        this.subject = ((CASLoginResponseBuilder) builder).subject;
        this.casCookie = ((CASLoginResponseBuilder) builder).casCookie;
        this.serviceTicketId = ((CASLoginResponseBuilder) builder).serviceTicketId;
    }

    public String getRespString() {
        return respString;
    }

    public String getSubject() {
        return subject;
    }

    public Cookie getCasCookie() {
        return casCookie;
    }

    public String getServiceTicketId() {
        return serviceTicketId;
    }


    public String getRelayState() {
        return relayState;
    }

    public String getRedirectUrl() {
        return redirectUrl;
    }

    public String getTenantDomain() {
        return tenantDomain;
    }

    public CASMessageContext getContext() {
        return (CASMessageContext) this.context;
    }

    public static class CASLoginResponseBuilder extends CASResponseBuilder {

        private static Log log = LogFactory.getLog(CASLoginResponseBuilder.class);

        private String respString;
        private String relayState;
        private String redirectUrl;
        private String subject;
        private String tenantDomain;
        private Cookie casCookie;
        private String serviceTicketId;

        public CASLoginResponseBuilder(IdentityMessageContext context) {
            super(context);
        }

        public CASLoginResponse build() {
            return new CASLoginResponse(this);
        }


        public CASLoginResponseBuilder setRespString(String respString) {
            this.respString = respString;
            return this;
        }

        public CASLoginResponseBuilder setServiceTicketId(String serviceTicketId) {
            this.serviceTicketId = serviceTicketId;
            return this;
        }

        public CASLoginResponseBuilder setCasCookie(Cookie cookie) {
            this.casCookie = cookie;
            return this;
        }

        public CASLoginResponseBuilder setSubject(String subject) {
            this.subject = subject;
            return this;
        }

        public CASLoginResponseBuilder setRelayState(String relayState) {
            this.relayState = relayState;
            return this;
        }

        public CASLoginResponseBuilder setRedirectUrl(String redirectUrl) {
            this.redirectUrl = redirectUrl;
            return this;
        }

        public CASLoginResponseBuilder setTenantDomain(String tenantDomain) {
            this.tenantDomain = tenantDomain;
            return this;
        }
    }
}
