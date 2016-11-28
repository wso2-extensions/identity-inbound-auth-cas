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
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationResult;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.sso.cas.configuration.CASConfiguration;
import org.wso2.carbon.identity.sso.cas.constants.CASSSOConstants;
import org.wso2.carbon.identity.sso.cas.context.CASMessageContext;
import org.wso2.carbon.identity.sso.cas.request.CASSpInitRequest;
import org.wso2.carbon.identity.sso.cas.response.CASLoginResponse;
import org.wso2.carbon.identity.sso.cas.response.CASResponse;
import org.wso2.carbon.identity.sso.cas.ticket.ServiceTicket;
import org.wso2.carbon.identity.sso.cas.ticket.TicketGrantingTicket;
import org.wso2.carbon.identity.sso.cas.util.CASSSOUtil;

import javax.servlet.http.Cookie;

public class SSOLoginProcessor extends IdentityProcessor {
    private static final String CAS_COOKIE_NAME = "CASTGC";
    private static Log log = LogFactory.getLog(SSOLoginProcessor.class);
    private static String ticketGrantingTicketId;
    TicketGrantingTicket ticketGrantingTicket;

    @Override
    public String getName() {
        return CASSSOConstants.CAS_SSO_LOGIN_PROCESSOR;
    }

    public int getPriority() {
        return CASSSOConstants.CAS_LOGIN_PROCESSOR_PRIORITY;
    }

    @Override
    public String getCallbackPath(IdentityMessageContext context) {
        return IdentityUtil.getServerURL(CASSSOConstants.IDENTITY, false, false);
    }

    @Override
    public boolean canHandle(IdentityRequest identityRequest) {
        IdentityMessageContext context = getContextIfAvailable(identityRequest);
        if (context != null) {
            if (context.getRequest() instanceof CASSpInitRequest) {
                return true;
            }
        }
        return false;
    }

    @Override
    public CASResponse.CASResponseBuilder process(IdentityRequest identityRequest) throws FrameworkException {
        Cookie casCookie = null;
        String serviceTicketId = null;
        CASMessageContext casMessageContext = (CASMessageContext) getContextIfAvailable(identityRequest);
        CASResponse.CASResponseBuilder builder = new CASLoginResponse.CASLoginResponseBuilder(casMessageContext);
        String serviceUrlFromRequest = casMessageContext.getServiceURL();
        AuthenticationResult authnResult = processResponseFromFrameworkLogin(casMessageContext, identityRequest);
        String acsURL = CASSSOUtil.getAcsUrl(serviceUrlFromRequest, casMessageContext.getRequest().getTenantDomain());
        if (authnResult.isAuthenticated()) {
            String ticketGrantingTicketId = getTicketGrantingTicketId(identityRequest);
            if (ticketGrantingTicketId == null) {
                ticketGrantingTicket = CASSSOUtil.createTicketGrantingTicket(authnResult, false);
            } else { // Existing TGT found
                ticketGrantingTicket = CASSSOUtil.getTicketGrantingTicket(ticketGrantingTicketId);
            }
            casCookie = storeTicketGrantingCookie(ticketGrantingTicket.getId(), identityRequest);
            ServiceTicket serviceTicket = ticketGrantingTicket.grantServiceTicket(acsURL);
            serviceTicketId = serviceTicket.getId();
        }
        ((CASLoginResponse.CASLoginResponseBuilder) builder).setCasCookie(casCookie);
        ((CASLoginResponse.CASLoginResponseBuilder) builder).setServiceTicketId(serviceTicketId);
        ((CASLoginResponse.CASLoginResponseBuilder) builder).setRedirectUrl(acsURL);
        return builder;
    }

    @Override
    public String getRelyingPartyId() {
        return null;
    }

    /**
     * Get the Ticket granting ticket Id.
     * @param req the request
     * @return the ticketGrantingTicketId
     */
    public String getTicketGrantingTicketId(IdentityRequest req) {
        Cookie ticketGrantingCookie = getTicketGrantingCookie(req);
        if (ticketGrantingCookie != null) {
            ticketGrantingTicketId = ticketGrantingCookie.getValue();
        }
        return ticketGrantingTicketId;
    }

    /**
     * Get the ticket granting cookie.
     * @param req the request
     * @return the cookie
     */
    public Cookie getTicketGrantingCookie(IdentityRequest req) {
        Cookie[] cookies = req.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(SSOLoginProcessor.CAS_COOKIE_NAME)) {
                    return cookie;
                }
            }
        }
        return null;
    }

    /**
     * Store the ticket granting cookie.
     * @param sessionId the sessionId
     * @param req the request
     * @return the stored ticket granting cookie
     */
    public Cookie storeTicketGrantingCookie(String sessionId, IdentityRequest req) {
        Cookie ticketGrantingCookie = getTicketGrantingCookie(req);
        if (ticketGrantingCookie == null) {
            ticketGrantingCookie = new Cookie(SSOLoginProcessor.CAS_COOKIE_NAME, sessionId);
        }
        ticketGrantingCookie.setPath(CASConfiguration.getBasePath());
        ticketGrantingCookie.setSecure(true);
        return ticketGrantingCookie;
    }
}