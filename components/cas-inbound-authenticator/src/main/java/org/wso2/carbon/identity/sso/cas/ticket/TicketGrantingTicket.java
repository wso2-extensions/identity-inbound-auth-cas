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
package org.wso2.carbon.identity.sso.cas.ticket;

import org.wso2.carbon.identity.sso.cas.constants.TicketConstants;
import org.wso2.carbon.identity.sso.cas.util.CASSSOUtil;

import java.util.HashMap;
import java.util.Map;

/**
 * CAS ticket-granting tickets (TGT) create service tickets for a service provider on behalf of the principal.
 * There is one TGT per WSO2 session and it is stored in a cookie, per the CAS protocol specification.
 * In the case of a proxy request, the proxy granting ticket generates proxy tickets for the requested
 * service provider.
 */
public class TicketGrantingTicket extends AbstractTicket {
    private static final long serialVersionUID = -2570624128249179398L;

    private boolean expired = false;

    private Map<String, ServiceTicket> serviceTickets;
    private String principal;

    public TicketGrantingTicket(String principal, boolean proxyRequest) {
        super(proxyRequest ? TicketConstants.PROXY_GRANTING_TICKET_PREFIX : TicketConstants.TICKET_GRANTING_TICKET_PREFIX, proxyRequest);
        serviceTickets = new HashMap<String, ServiceTicket>();
        this.principal = principal;
    }

    public synchronized ServiceTicket grantServiceTicket(final String service) {
        final ServiceTicket serviceTicket = new ServiceTicket(service, this, hasProxy());

        updateState();

        // Store a reference to the service ticket
        serviceTickets.put(serviceTicket.getId(), serviceTicket);

        // Persist the service ticket
        CASSSOUtil.storeServiceTicket(serviceTicket);

        return serviceTicket;
    }

    public final boolean equals(final Object object) {
        if (object == null
                || !(object instanceof TicketGrantingTicket)) {
            return false;
        }

        final TicketGrantingTicket ticket = (TicketGrantingTicket) object;

        return ticket.getId().equals(this.getId());
    }

    @Override
    public boolean isExpired() {
        return expired;
    }

    public String getPrincipal() {
        return principal;
    }
}
