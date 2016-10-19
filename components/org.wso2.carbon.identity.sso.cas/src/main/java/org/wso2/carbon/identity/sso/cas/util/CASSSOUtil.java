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
package org.wso2.carbon.identity.sso.cas.util;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.osgi.service.http.HttpService;
import org.wso2.carbon.CarbonException;
import org.wso2.carbon.core.util.AnonymousSessionUtil;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationRequestConfig;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.sso.cas.cache.*;
import org.wso2.carbon.identity.sso.cas.constants.CASSSOConstants;
import org.wso2.carbon.identity.sso.cas.exception.CASIdentityException;
import org.wso2.carbon.identity.sso.cas.exception.TicketNotFoundException;
import org.wso2.carbon.identity.sso.cas.ticket.ServiceTicket;
import org.wso2.carbon.identity.sso.cas.ticket.TicketGrantingTicket;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.claim.ClaimManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.ConfigurationContextService;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TimeZone;

public class CASSSOUtil {
    private static Log log = LogFactory.getLog(CASSSOUtil.class);
    private static HttpService httpService;
    private static BundleContext bundleContext;
    private static ConfigurationContextService configCtxService;
    protected static final String validationResponse = "<cas:serviceResponse xmlns:cas=\"http://www.yale.edu/tp/cas\">%s</cas:serviceResponse>";
    private static final String success = "<cas:authenticationSuccess>%s</cas:authenticationSuccess>";
    private static final String userTemplate = "<cas:user>%s</cas:user>";
    private static final String attributesWrapper = "<cas:attributes>%s</cas:attributes>";
    private static final String attributeTemplate = "<cas:%s>%s</cas:%s>";
    private static String failure = "<cas:authenticationFailure code=\"%s\">%s</cas:authenticationFailure>";
    private static SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
    private static RegistryService registryService;
    private static RealmService realmService;

    static {
        dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
    }

    public static BundleContext getBundleContext() {
        return CASSSOUtil.bundleContext;
    }

    public static void setBundleContext(BundleContext bundleContext) {
        CASSSOUtil.bundleContext = bundleContext;
    }


    public static RegistryService getRegistryService() {
        return registryService;
    }

    public static void setRegistryService(RegistryService registryService) {
        CASSSOUtil.registryService = registryService;
    }

    public static RealmService getRealmService() {
        return realmService;
    }

    public static void setRealmService(RealmService realmService) {
        CASSSOUtil.realmService = realmService;
    }

    public static ServiceProvider getServiceProviderByUrl(String serviceProviderUrl, String username) throws CASIdentityException{
        ServiceProvider serviceProvider = null;
        String tenantDomain = null;
        ApplicationManagementService appInfo = ApplicationManagementService.getInstance();
        try {

            if (username != null) {
                tenantDomain = MultitenantUtils.getTenantDomain(username);
                log.debug("getServiceProviderByUrl: tenant=" + tenantDomain);
            }

            if (tenantDomain == null) {
                tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
            }
            serviceProvider = appInfo.getServiceProviderByClientId(serviceProviderUrl,
                    CASSSOConstants.CAS_SSO, tenantDomain);
        } catch (IdentityApplicationManagementException e) {
            throw new CASIdentityException("Error occurred while getting service provider in the tenant domain" +
                    tenantDomain + "'", e);
        }
        return serviceProvider;
    }

    public static boolean isValidServiceProviderForServiceTicket(String serviceTicketId) {
        ServiceProvider serviceProvider = CASSSOUtil.getServiceTicket(serviceTicketId).getService();
        boolean isValidServiceProvider = false;

        for (InboundAuthenticationRequestConfig config : serviceProvider.getInboundAuthenticationConfig().
                getInboundAuthenticationRequestConfigs()) {
            String authType = config.getInboundAuthType();
            if (authType.equals(CASSSOConstants.CAS_SSO)) {
                isValidServiceProvider = true;
                break;
            }
        }
        return isValidServiceProvider;
    }

    public static ConfigurationContextService getConfigCtxService() {
        return configCtxService;
    }
    public static void setConfigCtxService(ConfigurationContextService configCtxService) {
        CASSSOUtil.configCtxService = configCtxService;
    }

    /*newly added*/
    public static HttpService getHttpService() {
        return httpService;
    }

    public static void setHttpService(HttpService httpService) {
        CASSSOUtil.httpService = httpService;
    }

    public static ServiceTicket getServiceTicket(String serviceTicketId) throws TicketNotFoundException {
        ServiceTicketCache cache = ServiceTicketCache.getInstance();

        ServiceTicketCacheKey key = new ServiceTicketCacheKey(serviceTicketId);

        ServiceTicketCacheEntry entry = (ServiceTicketCacheEntry) cache.getValueFromCache(key);

        if (entry != null) {
            return entry.getServiceTicket();
        } else {
            throw new TicketNotFoundException("CAS service ticket" + serviceTicketId + " not found", serviceTicketId);
        }
    }

    public static boolean isValidServiceTicket(String serviceTicketId) {
        try {
            ServiceTicket serviceTicket = getServiceTicket(serviceTicketId);

            return (serviceTicket != null);
        } catch (Exception ex) {
            return false;
        }
    }

    public static ServiceTicket consumeServiceTicket(String serviceTicketId) {
        ServiceTicket ticket;
        try {
            ServiceTicketCache cache = ServiceTicketCache.getInstance();
            ServiceTicketCacheKey key = new ServiceTicketCacheKey(serviceTicketId);
            ServiceTicketCacheEntry entry = (ServiceTicketCacheEntry) cache.getValueFromCache(key);
            ticket = entry.getServiceTicket();
            ticket.updateState();

            // Service tickets get cleaned up after one use
            if (ticket.isExpired()) {
                cache.clearCacheEntry(key);
            }
        } catch (Exception ex) {
            ticket = null;
        }
        return ticket;
    }

    public static TicketGrantingTicket createTicketGrantingTicket(String username, boolean proxyRequest) {
        TicketGrantingTicket ticket = new TicketGrantingTicket(username, proxyRequest);
        TicketGrantingTicketCache cache = TicketGrantingTicketCache.getInstance();
        TicketGrantingTicketCacheEntry entry = new TicketGrantingTicketCacheEntry();
        entry.setTicketGrantingTicket(ticket);

        TicketGrantingTicketCacheKey key = new TicketGrantingTicketCacheKey(ticket.getId());

        cache.addToCache(key, entry);

        return ticket;
    }

    public static void storeServiceTicket(ServiceTicket ticket) {
        ServiceTicketCache cache = ServiceTicketCache.getInstance();
        ServiceTicketCacheEntry entry = new ServiceTicketCacheEntry();
        entry.setServiceTicket(ticket);

        ServiceTicketCacheKey key = new ServiceTicketCacheKey(ticket.getId());

        cache.addToCache(key, entry);
    }

    public static TicketGrantingTicket getTicketGrantingTicket(String ticketGrantingTicketId) throws TicketNotFoundException {
        TicketGrantingTicketCache cache = TicketGrantingTicketCache.getInstance();

        TicketGrantingTicketCacheKey key = new TicketGrantingTicketCacheKey(ticketGrantingTicketId);

        TicketGrantingTicketCacheEntry entry = (TicketGrantingTicketCacheEntry) cache.getValueFromCache(key);

        if (entry != null) {
            return entry.getTicketGrantingTicket();
        } else {
            throw new TicketNotFoundException("CAS ticket granting ticket " + ticketGrantingTicketId + " not found",
                    ticketGrantingTicketId);
        }
    }

    public static Map<String, String> getUserClaimValues(String username, ClaimMapping[] claimMappings, String profile)
            throws IdentityException {
        try {
            List<String> requestedClaims = new ArrayList<String>();
            List<String> mappedClaims = new ArrayList<String>();

            UserRealm userRealm = AnonymousSessionUtil.getRealmByUserName(CASSSOUtil.getRegistryService(),
                    CASSSOUtil.getRealmService(),
                    username);

            for (ClaimMapping claimMapping : claimMappings) {
                mappedClaims.add(claimMapping.getLocalClaim().getClaimUri());
            }

            // Get all supported claims
            ClaimManager claimManager = userRealm.getClaimManager();
            org.wso2.carbon.user.api.ClaimMapping[] mappings = claimManager.getAllSupportClaimMappingsByDefault();

            for (org.wso2.carbon.user.api.ClaimMapping claimMapping : mappings) {
                requestedClaims.add(claimMapping.getClaim().getClaimUri());
            }

            // Get claim values for the user
            UserStoreManager userStoreManager = userRealm.getUserStoreManager();
            username = MultitenantUtils.getTenantAwareUsername(username);
            log.debug("getUserClaimValues: username=" + username);
            Map<String, String> localClaimValues = userStoreManager.getUserClaimValues(username,
                    requestedClaims.toArray(new String[requestedClaims.size()]), profile);

            String localClaimValue = null;
            String localClaimUri = null;
            String remoteClaimUri = null;

            // Remove the original claim URI and add the new mapped claim URI
            for (ClaimMapping claimMapping : claimMappings) {
                localClaimUri = claimMapping.getLocalClaim().getClaimUri();
                localClaimValue = localClaimValues.get(localClaimUri);
                remoteClaimUri = claimMapping.getRemoteClaim().getClaimUri();

                log.debug("getUserClaimValues: localClaimUri=" + localClaimUri + " ==> localClaimValue=" +
                        localClaimValue + " ==> remoteClaimUri=" + remoteClaimUri);

                if (localClaimValue != null) {
                    localClaimValues.remove(localClaimUri);
                    localClaimValues.put(remoteClaimUri, localClaimValue);
                }
            }

            // Remove the original claim URI and add the mapped attribute
            for (org.wso2.carbon.user.api.ClaimMapping claimMapping : mappings) {
                localClaimUri = claimMapping.getClaim().getClaimUri();
                localClaimValue = localClaimValues.get(localClaimUri);
                remoteClaimUri = claimMapping.getMappedAttribute();

                // Avoid re-inserting a mapped claim
                if (localClaimValue != null && !mappedClaims.contains(localClaimUri)) {
                    localClaimValues.remove(localClaimUri);
                    localClaimValues.put(remoteClaimUri, localClaimValue);
                }
            }

            // Clean up old strings
            localClaimUri = null;
            localClaimValue = null;
            remoteClaimUri = null;

            return localClaimValues;
        } catch (UserStoreException e) {
            log.info("Error while retrieving claims values", e);
            throw new CASIdentityException("Error while retrieving claims values", e);
        } catch (CarbonException | org.wso2.carbon.user.api.UserStoreException e) {
            log.info("Error while retrieving claims values", e);
            throw new CASIdentityException("Error while retrieving claim values", e);
        }
    }

    public static String buildAttributesXml(String username, ClaimMapping[] claimMapping) throws IdentityException {
        StringBuilder attributesXml = new StringBuilder();
        Map<String, String> claims = CASSSOUtil.getUserClaimValues(username, claimMapping, null);

        for (Map.Entry<String, String> entry : claims.entrySet()) {
            String scrubbedKey = entry.getKey().replaceAll(" ", "_");
            attributesXml.append(String.format(attributeTemplate, scrubbedKey, entry.getValue(), scrubbedKey));
        }
        log.debug("attributesXml:\n" + attributesXml);
        return attributesXml.toString();
    }

    /**
     * Build success response XML with user ID
     *
     * @param userId user id
     * @return success response XML
     */
    public static String buildSuccessResponse(String userId, String userAttributesXml) {
        StringBuilder responseAttributes = new StringBuilder();

        // Strip the domain prefix from the username for applications
        // that rely on the raw uid
        String rawUserId = UserCoreUtil.removeDomainFromName(userId);

        // user ID is always included
        responseAttributes.append(String.format(userTemplate, rawUserId));

        if (userAttributesXml != null) {
            responseAttributes.append(String.format(attributesWrapper, userAttributesXml));
        }
        return String.format(validationResponse, String.format(success, responseAttributes.toString()));
    }

    /**
     * Build error response XML with specific code and message
     *
     * @param errorCode    error code
     * @param errorMessage error message
     * @return error response XML
     */
    public static String buildFailureResponse(String errorCode, String errorMessage) {
        return String.format(validationResponse, String.format(failure, errorCode, errorMessage));
    }
}
