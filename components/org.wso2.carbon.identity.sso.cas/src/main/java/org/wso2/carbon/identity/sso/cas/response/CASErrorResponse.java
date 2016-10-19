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

import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;

public class CASErrorResponse extends CASResponse {

    private String errorResponse;
    private String acsUrl;
    private String status;
    private String messageLog;

    public CASErrorResponse(IdentityResponse.IdentityResponseBuilder responseBuilder) {

        super(responseBuilder);
        this.errorResponse = ((CASErrorResponseBuilder) responseBuilder).errorResponse;
        this.acsUrl = ((CASErrorResponseBuilder) responseBuilder).acsUrl;
        this.status = ((CASErrorResponseBuilder) responseBuilder).status;
        this.messageLog = ((CASErrorResponseBuilder) responseBuilder).messageLog;
    }

    public String getErrorResponse() {
        return errorResponse;
    }

    public String getAcsUrl() {
        return acsUrl;
    }

    public String getStatus() {
        return status;
    }

    public String getMessageLog() {
        return messageLog;
    }

    public static class CASErrorResponseBuilder extends CASResponseBuilder {

        private String errorResponse;
        private String acsUrl;
        private String status;
        private String messageLog;

        public CASErrorResponseBuilder(IdentityMessageContext context) {
            super(context);
        }

        public CASErrorResponse build() {
            return new CASErrorResponse(this);
        }

        public CASErrorResponseBuilder setErrorResponse(String response) {
            this.errorResponse = response;
            return this;
        }

        public CASErrorResponseBuilder setAcsUrl(String acsUrl) {
            this.acsUrl = acsUrl;
            return this;
        }

        public CASErrorResponseBuilder setStatus(String status) {
            this.status = status;
            return this;
        }

        public CASErrorResponseBuilder setMessageLog(String messageLog) {
            this.messageLog = messageLog;
            return this;
        }

    }
}
