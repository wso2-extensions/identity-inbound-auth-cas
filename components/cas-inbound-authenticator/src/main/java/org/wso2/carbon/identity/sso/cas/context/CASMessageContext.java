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
package org.wso2.carbon.identity.sso.cas.context;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.sso.cas.constants.CASConstants;
import org.wso2.carbon.identity.sso.cas.request.CASIdentityRequest;
import org.wso2.carbon.identity.sso.cas.request.CASServiceValidateRequest;

import java.io.Serializable;
import java.util.Map;

public class CASMessageContext<T1 extends Serializable, T2 extends Serializable> extends IdentityMessageContext {
    private static Log log = LogFactory.getLog(CASMessageContext.class);

    public CASMessageContext(CASIdentityRequest request, Map<T1, T2> parameters) {
        super(request, parameters);
    }

    @Override
    public CASIdentityRequest getRequest() {
        return (CASIdentityRequest) request;
    }

    public CASServiceValidateRequest getValidateRequest() {
        return (CASServiceValidateRequest) request;
    }

    public String getServiceURL() {
        return request.getParameter(CASConstants.CASSSOConstants.SERVICE_PROVIDER_ARGUMENT);
    }
}
