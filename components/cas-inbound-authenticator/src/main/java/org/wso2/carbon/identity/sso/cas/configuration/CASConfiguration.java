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
package org.wso2.carbon.identity.sso.cas.configuration;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.sso.cas.constants.CASSSOConstants;

public class CASConfiguration {
    private static final String CAS_CONTEXT_PATH = "CAS.ContextPath";
    private static Log log = LogFactory.getLog(CASConfiguration.class);
    private static String basePath = CASSSOConstants.CAS_BASEPATH; // Default context path

    static {
        try {
            String casBasePath = IdentityUtil.getProperty(CASConfiguration.CAS_CONTEXT_PATH);

            if (casBasePath == null || casBasePath.trim().length() == 0) {
                throw new Exception();
            } else {
                basePath = casBasePath;
            }
        } catch (Exception ex) {
            log.error("CAS base path not found. Using default value.");
        }
    }

    public static String getBasePath() {
        return basePath;
    }
}