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
package org.wso2.carbon.identity.sso.cas.util;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.sso.cas.constants.CASConstants;

import java.util.Locale;
import java.util.ResourceBundle;


/**
 * Resource abstraction that attempts to read from disk for an override and failover to classpath
 */
public class CASResourceReader {
    private static CASResourceReader instance = new CASResourceReader();
    private static final Log log = LogFactory.getLog(CASResourceReader.class);

    private CASResourceReader() {

    }

    public static CASResourceReader getInstance() {
        return instance;
    }

    public String getLocalizedString(String key, Locale locale) {
        ResourceBundle bundle = ResourceBundle.getBundle(CASConstants.CASSSOConstants.RESOURCE_BUNDLE, locale);
        if (bundle != null) {
            return bundle.getString(key);
        } else {
            return null;
        }
    }
}
