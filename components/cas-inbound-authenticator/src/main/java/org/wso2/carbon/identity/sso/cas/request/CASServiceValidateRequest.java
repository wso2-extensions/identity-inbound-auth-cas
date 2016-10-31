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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.sso.cas.constants.CASSSOConstants;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Locale;

public class CASServiceValidateRequest extends CASIdentityRequest {
    private static Log log = LogFactory.getLog(CASServiceValidateRequest.class);
    Locale locale;

    public CASServiceValidateRequest(IdentityRequest.IdentityRequestBuilder builder) {
        super((CASIdentityRequestBuilder) builder);
        this.locale = ((CASServiceValidateRequest.CASServiceValidateRequestBuilder) builder).locale;
    }

    public String getServiceRequest() {
        return CASSSOConstants.SERVICE_PROVIDER_ARGUMENT;
    }

    public String getServiceTicket() {
        return CASSSOConstants.SERVICE_TICKET_ARGUMENT;
    }

    public Locale getLocale() {
        return this.locale;
    }

    public static class CASServiceValidateRequestBuilder extends CASIdentityRequestBuilder {

        Locale locale;

        public CASServiceValidateRequestBuilder(HttpServletRequest request, HttpServletResponse response) {
            super(request, response);
        }

        public CASServiceValidateRequestBuilder() {
        }

        @Override
        public CASServiceValidateRequest build() {
            return new CASServiceValidateRequest(this);
        }

        public CASServiceValidateRequestBuilder setLocale(HttpServletRequest request) {
            this.locale = request.getLocale();
            return this;
        }
    }
}


