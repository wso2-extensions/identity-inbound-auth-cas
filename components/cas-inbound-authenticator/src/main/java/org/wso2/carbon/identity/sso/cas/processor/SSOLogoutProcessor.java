/*
 *  Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkLogoutResponse;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityProcessor;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.sso.cas.constants.CASConstants;
import org.wso2.carbon.identity.sso.cas.context.CASMessageContext;
import org.wso2.carbon.identity.sso.cas.request.CASLogoutRequest;

import java.util.HashMap;

/**
 *
 */
public class SSOLogoutProcessor extends IdentityProcessor {
    private static Log log = LogFactory.getLog(SSOLogoutProcessor.class);

    /**
     * @return the name of processor
     */
    @Override
    public String getName() {

        return CASConstants.CAS_CONFIG_NAME;
    }

    /**
     * @return the priority
     */
    @Override
    public int getPriority() {

        return 4;
    }

    /**
     * @param context        the message context
     * @return the server URL
     */
    @Override
    public String getCallbackPath(IdentityMessageContext context) {

        return IdentityUtil.getServerURL("/authenticationendpoint/samlsso_logout.do", false, false);
    }

    /**
     * @param identityRequest       the message context
     * @return true if this possessor could handle request and false if could not
     */
    @Override
    public boolean canHandle(IdentityRequest identityRequest) {

        return identityRequest instanceof CASLogoutRequest;
    }

    /**
     * @param identityRequest       the identity message context
     * @return the logout response
     * @throws FrameworkException
     */
    @Override
    public FrameworkLogoutResponse.FrameworkLogoutResponseBuilder process(IdentityRequest identityRequest) {

        CASMessageContext messageContext = new CASMessageContext((CASLogoutRequest) identityRequest, new
                HashMap<String, String>());

        FrameworkLogoutResponse.FrameworkLogoutResponseBuilder logoutResponseBuilder = this.buildResponseForFrameworkLogout(messageContext);

        return logoutResponseBuilder;
    }

    /**
     * @return null
     */
    @Override
    public String getRelyingPartyId() {

        return null;
    }

    /**
     * @param identityMessageContext        the identity message context
     * @return the id of relying party
     */
    @Override
    public String getRelyingPartyId(IdentityMessageContext identityMessageContext) {

        return identityMessageContext.getRelyingPartyId();
    }

}
