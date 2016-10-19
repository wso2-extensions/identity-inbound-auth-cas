/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.sso.cas.constants.CASSSOConstants;

public class CASConfigs extends AbstractInboundAuthenticatorConfig {

    private static Log log = LogFactory.getLog(CASConfigs.class);

    @Override
    public String getAuthKey() {
        return null;
    }

    @Override
    public String getConfigName() {
        return "cas";
    }

    //this is the authType
    @Override
    public String getName() {
        return CASSSOConstants.CAS_SSO;
    }

    @Override
    public String getFriendlyName() {
        return "CAS";
    }

    @Override
    public Property[] getConfigurationProperties() {

        Property appType = new Property();
        appType.setName(IdentityConstants.ServerConfig.WELLKNOWN_APPLICATION_TYPE);
        appType.setType("hidden");
        appType.setValue(getConfigName());
        appType.setDisplayName(IdentityConstants.ServerConfig.WELLKNOWN_APPLICATION_TYPE);

        Property service = new Property();
        service.setName(CASSSOConstants.SERVICE);
        service.setDisplayName(CASSSOConstants.CAS_SERVICE_URL);

        return new Property[]{appType, service};
    }

    @Override
    public String getRelyingPartyKey() {
        return CASSSOConstants.SERVICE;
    }
}
