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
package org.wso2.carbon.identity.sso.cas.constants;

public class CASConstants {
    public static final String CAS_CONFIG_NAME = "cas";
    public static final String CAS_FRIENDLY_NAME = "CAS Configuration";
    public static final String CAS_APP_TYPE = "hidden";
    public static final String CAS_LOGOUT_URI = "logout";

    /**
     * CAS specific SSO constants.
     */
    public static class CASSSOConstants {
        public static final String CAS_SERVICE_URL = "Service Url";
        public static final String SERVICE_TICKET_ARGUMENT = "ticket";
        public static final String SERVICE_PROVIDER_ARGUMENT = "service";
        public static final String STATUS = "status";
        public static final String STATUS_MSG = "statusMsg";
        public static final String RESOURCE_BUNDLE = "org.wso2.carbon.identity.sso.cas.i18n.Resources";
        public static final String NOTIFICATION_ENDPOINT = "/authenticationendpoint/generic-exception-response.jsp";
    }
    /**
     * CAS constants which are used in error case.
     */
    public static class CASErrorConstants {
        public static final String INVALID_REQUEST_CODE = "INVALID_REQUEST";
        public static final String INVALID_REQUEST_MESSAGE = "cas.invalid.request.message";
        public static final String INVALID_TICKET_CODE = "INVALID_TICKET";
        public static final String INVALID_TICKET_MESSAGE = "cas.invalid.ticket.message";
        public static final String INVALID_SERVICE_CODE = "INVALID_SERVICE";
        public static final String INVALID_SERVICE_MESSAGE = "cas.invalid.service.message";
        public static final String INTERNAL_ERROR_CODE = "INTERNAL_ERROR";
        public static final String INTERNAL_ERROR_MESSAGE = "cas.internal.error.message";
    }

    public static class TicketConstants {
        public static final String SERVICE_TICKET_PREFIX = "ST";
        public static final String TICKET_GRANTING_TICKET_PREFIX = "TGT";
        public static final String PROXY_GRANTING_TICKET_PREFIX = "PGT";
        public static final String PROXY_TICKET_PREFIX = "PT";
    }
}
