//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//

package org.wso2.carbon.identity.sso.cas.processor;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkLogoutResponse;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityProcessor;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationResult;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.sso.cas.configuration.CASConfiguration;
import org.wso2.carbon.identity.sso.cas.constants.CASConstants;
import org.wso2.carbon.identity.sso.cas.context.CASMessageContext;
import org.wso2.carbon.identity.sso.cas.request.CASLogoutRequest;
import org.wso2.carbon.identity.sso.cas.request.CASSInitRequest;
import org.wso2.carbon.identity.sso.cas.response.CASLoginResponse.CASLoginResponseBuilder;
import org.wso2.carbon.identity.sso.cas.response.CASResponse.CASResponseBuilder;
import org.wso2.carbon.identity.sso.cas.ticket.ServiceTicket;
import org.wso2.carbon.identity.sso.cas.ticket.TicketGrantingTicket;
import org.wso2.carbon.identity.sso.cas.util.CASSSOUtil;

import javax.servlet.http.Cookie;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;

public class SSOLogoutProcessor extends IdentityProcessor {
    private static Log log = LogFactory.getLog(SSOLogoutProcessor.class);

    @Override
    public String getName() {
        return CASConstants.CAS_CONFIG_NAME;
    }

    public int getPriority() {
        return 4;
    }

    @Override
    public String getCallbackPath(IdentityMessageContext context) {
        return IdentityUtil.getServerURL("/authenticationendpoint/samlsso_logout.do", false, false);
    }

    @Override
    public boolean canHandle(IdentityRequest identityRequest) {
        return identityRequest instanceof CASLogoutRequest;
    }

    public FrameworkLogoutResponse.FrameworkLogoutResponseBuilder process(IdentityRequest identityRequest) throws FrameworkException {

        CASMessageContext messageContext = new CASMessageContext((CASLogoutRequest) identityRequest, new
                HashMap<String, String>());

        FrameworkLogoutResponse.FrameworkLogoutResponseBuilder logoutResponseBuilder = this.buildResponseForFrameworkLogout(messageContext);

        return logoutResponseBuilder;
    }

    public String getRelyingPartyId() {
        return null;
    }

    public String getRelyingPartyId(IdentityMessageContext identityMessageContext) {
        return identityMessageContext.getRelyingPartyId();
    }

}
