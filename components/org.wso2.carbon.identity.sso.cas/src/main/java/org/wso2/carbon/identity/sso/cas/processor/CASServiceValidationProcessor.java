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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityProcessor;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.sso.cas.context.CASMessageContext;
import org.wso2.carbon.identity.sso.cas.request.CASServiceValidateRequest;
import org.wso2.carbon.identity.sso.cas.response.CASResponse;
import org.wso2.carbon.identity.sso.cas.response.CASServiceValidationResponse;

import java.util.HashMap;

public class CASServiceValidationProcessor extends IdentityProcessor {
    private static Log log = LogFactory.getLog(CASServiceValidationProcessor.class);
    private String relyingParty;

    @Override
    public String getName() {
        return "CASServiceValidationProcessor";
    }

    public int getPriority() {
        return 1;
    }

    @Override
    public String getCallbackPath(IdentityMessageContext context) {
        return IdentityUtil.getServerURL("identity", false, false);
    }

    @Override
    public String getRelyingPartyId() {
        return this.relyingParty;
    }

    @Override
    public boolean canHandle(IdentityRequest identityRequest) {
        if (identityRequest instanceof CASServiceValidateRequest && ((CASServiceValidateRequest) identityRequest).getServiceRequest
                () != null && ((CASServiceValidateRequest) identityRequest).getServiceTicket() != null) {
            return true;
        }
        return false;
    }

    @Override
    public CASResponse.CASResponseBuilder process(IdentityRequest identityRequest) throws FrameworkException {

        CASMessageContext messageContext = new CASMessageContext((CASServiceValidateRequest) identityRequest, new
                HashMap<String, String>());
        this.relyingParty = messageContext.getRelayState();
        String redirectURL = messageContext.getServiceURL();
        CASResponse.CASResponseBuilder builder = new CASServiceValidationResponse.CASServiceValidationResponseBuilder(messageContext);
        ((CASServiceValidationResponse.CASServiceValidationResponseBuilder) builder).buildResponse();
        ((CASServiceValidationResponse.CASServiceValidationResponseBuilder) builder).setRedirectUrl(redirectURL);
        return builder;
    }
}
