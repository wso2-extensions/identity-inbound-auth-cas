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
package org.wso2.carbon.identity.sso.cas.constants;

public class CASSSOConstants {
    public static final String CAS_SSO = "cas";
    public static final String CAS_SERVICE_URL = "Service Url";
    public static final String SERVICE_TICKET_ARGUMENT = "ticket";
    public static final String SERVICE_PROVIDER_ARGUMENT = "service";
    public static final String STATUS = "status";
    public static final String STATUS_MSG = "statusMsg";
    public static final String RESOURCE_BUNDLE = "org.wso2.carbon.identity.sso.cas.i18n.Resources";
    public static final String NOTIFICATION_ENDPOINT = "/authenticationendpoint/generic-exception-response.jsp";
    public static final String HOSTNAME = "HostName";
    public static final String HTTP_CASRESPONSE_FACTORY = "HttpCASResponseFactory";
    public static final String CAS_IDENTITY_REQUEST_FACTORY = "CASIdentityRequestFactory";
    public static final String CAS_SSO_LOGIN_PROCESSOR = "SSOLoginProcessor";
    public static final String IDENTITY = "identity";
    public static final String CAS_CONFIG_NAME = "cas";
    public static final String CAS_FRIENDLY_NAME = "CAS Configuration";
    public static final String CAS_BASEPATH = "/cas";
    public static final int VALIDATION_PROCESSOR_PRIORITY = 1;
    public static final int SP_INIT_PROCESSOR_PRIORITY = 3;
    public static final int CAS_LOGIN_PROCESSOR_PRIORITY = 2;
    public static final String CAS_VALIDATION_PROCESSOR = "CASServiceValidationProcessor";
}