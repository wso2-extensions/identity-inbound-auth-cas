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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.sso.cas.constants.TicketConstants;

/**
 * CAS service tickets are associated to a service provider by a ticket-granting ticket and
 * can only be used once. In the case of a proxy request, the proxy ticket is associated to the
 * requested service provider.
 */
public class ServiceTicket extends AbstractTicket {
    private static final long serialVersionUID = 3163737436365602898L;
    private static Log log = LogFactory.getLog(ServiceTicket.class);
    private TicketGrantingTicket ticketGrantingTicket;
    private ServiceProvider service;
    private boolean used = false;

    public ServiceTicket(ServiceProvider serviceProvider, TicketGrantingTicket parentTicket, boolean proxyRequest) {
        super(proxyRequest ? TicketConstants.PROXY_TICKET_PREFIX : TicketConstants.SERVICE_TICKET_PREFIX, proxyRequest);
        ticketGrantingTicket = parentTicket;
        //todo STORE THE URL NOT WHOLE SERVICE PROVIDER
        service = serviceProvider;
    }

    public TicketGrantingTicket getParentTicket() {
        return ticketGrantingTicket;
    }

    public ServiceProvider getService() {
        return service;
    }

    @Override
    public boolean isExpired() {
        return used || super.isExpired();
    }

    @Override
    public void updateState() {
        super.updateState();
        used = true;
    }
}
