/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.sso.cas.configuration;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.mgt.AbstractInboundAuthenticatorConfig;
import org.wso2.carbon.identity.sso.cas.constants.CASConstants;

public class CASConfigs extends AbstractInboundAuthenticatorConfig {

    private static final Log log = LogFactory.getLog(CASConfigs.class);

    @Override
    public String getConfigName() {
        return CASConstants.CAS_CONFIG_NAME;
    }

    //this is the authType
    @Override
    public String getName() {
        return CASConstants.CAS_CONFIG_NAME;
    }

    @Override
    public String getFriendlyName() {
        return CASConstants.CAS_FRIENDLY_NAME;
    }

    @Override
    public Property[] getConfigurationProperties() {
        Property service = new Property();
        service.setName(CASConstants.CASSSOConstants.SERVICE_PROVIDER_ARGUMENT);
        service.setDisplayName(CASConstants.CASSSOConstants.CAS_SERVICE_URL);

        return new Property[]{service};
    }

    @Override
    public String getRelyingPartyKey() {
        return CASConstants.CASSSOConstants.SERVICE_PROVIDER_ARGUMENT;
    }
}