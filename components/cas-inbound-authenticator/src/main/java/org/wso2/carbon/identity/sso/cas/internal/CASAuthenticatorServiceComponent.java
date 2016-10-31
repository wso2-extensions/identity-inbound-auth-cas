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
package org.wso2.carbon.identity.sso.cas.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.http.HttpService;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityRequestFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponseFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityProcessor;
import org.wso2.carbon.identity.application.mgt.AbstractInboundAuthenticatorConfig;
import org.wso2.carbon.identity.sso.cas.configuration.CASConfigs;
import org.wso2.carbon.identity.sso.cas.processor.CASServiceValidationProcessor;
import org.wso2.carbon.identity.sso.cas.processor.SPInitSSOAuthnRequestProcessor;
import org.wso2.carbon.identity.sso.cas.processor.SSOLoginProcessor;
import org.wso2.carbon.identity.sso.cas.request.CASIdentityRequestFactory;
import org.wso2.carbon.identity.sso.cas.response.HttpCASResponseFactory;
import org.wso2.carbon.identity.sso.cas.util.CASSSOUtil;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.ConfigurationContextService;

import java.util.Hashtable;


/**
 * @scr.component name="identity.sso.cas.component" immediate="true"
 * @scr.reference name="registry.service"
 * interface="org.wso2.carbon.registry.core.service.RegistryService"
 * cardinality="1..1" policy="dynamic" bind="setRegistryService"
 * unbind="unsetRegistryService"
 * @scr.reference name="config.context.service"
 * interface="org.wso2.carbon.utils.ConfigurationContextService" cardinality="1..1"
 * policy="dynamic" bind="setConfigurationContextService"
 * unbind="unsetConfigurationContextService"
 * @scr.reference name="user.realmservice.default" interface="org.wso2.carbon.user.core.service.RealmService"
 * cardinality="1..1" policy="dynamic" bind="setRealmService"
 * unbind="unsetRealmService"
 * @scr.reference name="osgi.httpservice" interface="org.osgi.service.http.HttpService"
 * cardinality="1..1" policy="dynamic" bind="setHttpService"
 * unbind="unsetHttpService"
 * @scr.reference name="processor.request"
 * interface="SPInitSSOAuthnRequestProcessor" cardinality="0..n"
 * policy="dynamic" bind="addAuthnRequestProcessor" unbind="removeAuthnRequestProcessor"
 * @scr.reference name="request.factory"
 * interface="CASIdentityRequestFactory" cardinality="0..n"
 * policy="dynamic" bind="addCASRequestFactory" unbind="removeCASRequestFactory"
 */

public class CASAuthenticatorServiceComponent {

    private static Log log = LogFactory.getLog(CASAuthenticatorServiceComponent.class);
    private SPInitSSOAuthnRequestProcessor authnRequestProcessor;
    private CASIdentityRequestFactory casRequestFactory;

    protected void activate(ComponentContext ctxt) {

        CASSSOUtil.setBundleContext(ctxt.getBundleContext());
        ctxt.getBundleContext().registerService(HttpIdentityRequestFactory.class.getName(), new
                CASIdentityRequestFactory(), null);
        ctxt.getBundleContext().registerService(HttpIdentityResponseFactory.class.getName(), new
                HttpCASResponseFactory(), null);
        ctxt.getBundleContext().registerService(IdentityProcessor.class.getName(), new SPInitSSOAuthnRequestProcessor
                (), null);
        ctxt.getBundleContext().registerService(IdentityProcessor.class.getName(), new SSOLoginProcessor(), null);
        ctxt.getBundleContext().registerService(IdentityProcessor.class.getName(), new CASServiceValidationProcessor(), null);
        CASConfigs cas = new CASConfigs();
        Hashtable<String, String> casProps = new Hashtable<String, String>();
        ctxt.getBundleContext().registerService(AbstractInboundAuthenticatorConfig.class, cas, casProps);
        log.info("Identity CAS SSO bundle is activated");
    }

    protected void addCASRequestFactory(CASIdentityRequestFactory requestFactory) {
        if (log.isDebugEnabled()) {
            log.debug("Adding CASIdentityRequestFactory " + requestFactory.getName());
        }
        this.casRequestFactory = requestFactory;
    }

    protected void removeCASRequestFactory(CASIdentityRequestFactory requestFactory) {
        if (log.isDebugEnabled()) {
            log.debug("Removing CASIdentityRequestFactory ");
        }
        this.casRequestFactory = null;
    }

    protected void addAuthnRequestProcessor(SPInitSSOAuthnRequestProcessor processor) {
        if (log.isDebugEnabled()) {
            log.debug("Adding SPInitSSOAuthnRequestProcessor " + processor.getName());
        }
        this.authnRequestProcessor = processor;
    }

    protected void removeAuthnRequestProcessor(SPInitSSOAuthnRequestProcessor processor) {
        if (log.isDebugEnabled()) {
            log.debug("Removing SPInitSSOAuthnRequestProcessor ");
        }
        this.authnRequestProcessor = null;
    }

    protected void deactivate(ComponentContext ctxt) {
        if (log.isDebugEnabled()) {
            log.info("Identity CAS SSO bundle is deactivated");
        }
    }

    protected void setRegistryService(RegistryService registryService) {
        if (log.isDebugEnabled()) {
            log.debug("RegistryService set in Identity CAS SSO bundle");
        }
        try {
            CASSSOUtil.setRegistryService(registryService);
        } catch (Throwable e) {
            log.error("Failed to get a reference to the Registry in CAS SSO bundle", e);
        }
    }

    protected void unsetRegistryService(RegistryService registryService) {
        if (log.isDebugEnabled()) {
            log.debug("RegistryService unset in CAS SSO bundle");
        }
        CASSSOUtil.setRegistryService(null);
    }

    protected void setRealmService(RealmService realmService) {
        if (log.isDebugEnabled()) {
            log.debug("Realm Service is set in the CAS SSO bundle");
        }
        CASSSOUtil.setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {
        if (log.isDebugEnabled()) {
            log.debug("Realm Service is set in the CAS SSO bundle");
        }
        CASSSOUtil.setRegistryService(null);
    }

    protected void setHttpService(HttpService httpService) {
        if (log.isDebugEnabled()) {
            log.debug("HTTP Service is set in the CAS SSO bundle");
        }
        CASSSOUtil.setHttpService(httpService);
    }

    protected void unsetHttpService(HttpService httpService) {
        if (log.isDebugEnabled()) {
            log.debug("HTTP Service is unset in the CAS SSO bundle");
        }
        CASSSOUtil.setHttpService(null);
    }

    protected void setConfigurationContextService(ConfigurationContextService configCtxService) {
        if (log.isDebugEnabled()) {
            log.debug("Configuration Context Service is set in the CAS SSO bundle");
        }
        CASSSOUtil.setConfigCtxService(configCtxService);
    }

    protected void unsetConfigurationContextService(ConfigurationContextService configCtxService) {
        if (log.isDebugEnabled()) {
            log.debug("Configuration Context Service is unset in the CAS SSO bundle");
        }
        CASSSOUtil.setConfigCtxService(null);
    }
}

