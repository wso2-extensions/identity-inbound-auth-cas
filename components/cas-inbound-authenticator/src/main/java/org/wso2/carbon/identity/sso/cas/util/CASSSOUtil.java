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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.osgi.service.http.HttpService;
import org.wso2.carbon.CarbonException;
import org.wso2.carbon.core.util.AnonymousSessionUtil;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationResult;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationRequestConfig;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.sso.cas.cache.*;
import org.wso2.carbon.identity.sso.cas.constants.CASConstants;
import org.wso2.carbon.identity.sso.cas.exception.CAS2ClientException;
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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class CASSSOUtil {
    protected static final String validationResponse = "<cas:serviceResponse xmlns:cas=\"http://www.yale.edu/tp/cas\">%s</cas:serviceResponse>";
    private static final String success = "<cas:authenticationSuccess>%s</cas:authenticationSuccess>";
    private static final String userTemplate = "<cas:user>%s</cas:user>";
    private static final String attributesWrapper = "<cas:attributes>%s</cas:attributes>";
    private static final String attributeTemplate = "<cas:%s>%s</cas:%s>";
    private static Log log = LogFactory.getLog(CASSSOUtil.class);
    private static HttpService httpService;
    private static BundleContext bundleContext;
    private static ConfigurationContextService configCtxService;
    private static String failure = "<cas:authenticationFailure code=\"%s\">%s</cas:authenticationFailure>";
    private static RegistryService registryService;
    private static RealmService realmService;

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


    public static ConfigurationContextService getConfigCtxService() {
        return configCtxService;
    }

    public static void setConfigCtxService(ConfigurationContextService configCtxService) {
        CASSSOUtil.configCtxService = configCtxService;
    }


    public static HttpService getHttpService() {
        return httpService;
    }

    public static void setHttpService(HttpService httpService) {
        CASSSOUtil.httpService = httpService;
    }

    public static ServiceProvider getServiceProviderByUrl(String serviceProviderUrl, String tenantDomain) throws
            CASIdentityException {
        ServiceProvider serviceProvider = null;
        ApplicationManagementService appInfo = ApplicationManagementService.getInstance();
        try {
            if (tenantDomain == null) {
                tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
            }
            serviceProvider = appInfo
                    .getServiceProviderByClientId(serviceProviderUrl, CASConstants.CAS_CONFIG_NAME, tenantDomain);
        } catch (IdentityApplicationManagementException e) {
            throw new CASIdentityException("Error occurred while getting service provider in the tenant domain" +
                    tenantDomain + "'", e);
        }
        return serviceProvider;
    }

    public static String getAcsUrl(String serviceProviderUrl, String tenantDomain) throws CAS2ClientException {
        ServiceProvider serviceProvider;
        String acsUrl = null;
        try {
            serviceProvider = getServiceProviderByUrl(serviceProviderUrl, tenantDomain);
            for (InboundAuthenticationRequestConfig authenticationRequestConfig : serviceProvider
                    .getInboundAuthenticationConfig().getInboundAuthenticationRequestConfigs()) {
                if (StringUtils.equals(authenticationRequestConfig.getInboundAuthType(), CASConstants.CAS_CONFIG_NAME)
                        && StringUtils.equals(authenticationRequestConfig.getInboundAuthKey(), serviceProviderUrl)) {
                    acsUrl = authenticationRequestConfig.getInboundAuthKey();
                    break;
                }
            }
        } catch (CASIdentityException e) {
            throw CAS2ClientException.error("Error while getting acsUrl from Inbound configuration", e);
        }
        return acsUrl;
    }

    public static boolean isValidAcsUrlForServiceTicket(String serviceProviderUrl, String serviceTicketId) {
        String acsUrl = CASSSOUtil.getServiceTicket(serviceTicketId).getService();
        boolean isValidAcsUrl = false;
        if (acsUrl.equals(serviceProviderUrl)) {
            isValidAcsUrl = true;
        }
        return isValidAcsUrl;
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

    public static TicketGrantingTicket createTicketGrantingTicket(AuthenticationResult authenticationResult, boolean proxyRequest) {
        TicketGrantingTicket ticket = new TicketGrantingTicket(authenticationResult, proxyRequest);
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

    public static TicketGrantingTicket getTicketGrantingTicket(String ticketGrantingTicketId)
            throws TicketNotFoundException {
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

    public static Map<String, String> getUserClaimValues(AuthenticationResult result, ClaimMapping[] claimMappings,
                                                         String profile)
            throws IdentityException {
        try {
            String username = String.valueOf(result.getSubject());
            List<String> allClaims = new ArrayList<String>();
            Map<String, String> claimsMap = new HashMap<String, String>();
            List<String> mappedClaims = new ArrayList<String>();

            UserRealm userRealm = AnonymousSessionUtil.getRealmByUserName(CASSSOUtil.getRegistryService(),
                    CASSSOUtil.getRealmService(),
                    username);

            for (ClaimMapping claimMapping : claimMappings) {
                mappedClaims.add(claimMapping.getLocalClaim().getClaimUri());
            }

            // Get all supported claims
            ClaimManager claimManager = userRealm.getClaimManager();
            org.wso2.carbon.user.api.ClaimMapping[] mappings = claimManager.getAllClaimMappings();
            for (org.wso2.carbon.user.api.ClaimMapping claimMapping : mappings) {
                allClaims.add(claimMapping.getClaim().getClaimUri());
                if (log.isDebugEnabled()) {
                    log.debug("adding requested claim: " + claimMapping.getClaim().getClaimUri());
                }
            }

            // Get claim values for the user
            UserStoreManager userStoreManager = null;
            boolean localAuthentication = false;
            try {
                userStoreManager = userRealm.getUserStoreManager();
                localAuthentication = userStoreManager.isExistingUser(username);
            } catch (UserStoreException e) {
                // User came from federated authentication
                log.warn("Error while retrieving the user from federated authentication, e");
            }
            username = MultitenantUtils.getTenantAwareUsername(username);
            if (log.isDebugEnabled()) {
                log.debug("getUserClaimValues: username=" + username);
            }
            Map<String, String> localClaimValues = new HashMap<String, String>();

            if (userStoreManager == null || !localAuthentication) {
                Map<ClaimMapping, String> userAttributes = result.getSubject().getUserAttributes();
                if (userAttributes != null) {
                    for (Map.Entry<ClaimMapping, String> entry : userAttributes.entrySet()) {
                        if (log.isDebugEnabled()) {
                            log.debug(entry.getKey().getLocalClaim().getClaimUri() + " ==> " + entry.getValue());
                        }
                        claimsMap.put(entry.getKey().getLocalClaim().getClaimUri(), entry.getValue());
                    }
                }
            } else {
                claimsMap = userStoreManager.getUserClaimValues(username,
                        allClaims.toArray(new String[allClaims.size()]), profile);
            }

            Map<String, String> requestedClaim = new HashMap<String, String>();
            String localClaimValue = null;
            String localClaimUri = null;
            String remoteClaimUri = null;

            // Remove the original claim URI and add the new mapped claim URI
            for (ClaimMapping claimMapping : claimMappings) {
                localClaimUri = claimMapping.getLocalClaim().getClaimUri();
                localClaimValue = claimsMap.get(localClaimUri);
                remoteClaimUri = claimMapping.getRemoteClaim().getClaimUri();
                if (log.isDebugEnabled()) {
                    log.debug("getUserClaimValues: localClaimUri=" + localClaimUri + " ==> localClaimValue="
                            + localClaimValue + " ==> remoteClaimUri=" + remoteClaimUri);
                }
                if (localClaimValue != null) {
                    localClaimValues.put(remoteClaimUri, localClaimValue);
                }
            }

            // Remove the original claim URI and add the mapped attribute
            if (mappedClaims.isEmpty()) {
                for (org.wso2.carbon.user.api.ClaimMapping claimMapping : mappings) {
                    localClaimUri = claimMapping.getClaim().getClaimUri();
                    localClaimValue = claimsMap.get(localClaimUri);
                    remoteClaimUri = claimMapping.getMappedAttribute();

                    // Avoid re-inserting a mapped claim
                    if (localClaimValue != null) {
                        localClaimValues.put(remoteClaimUri, localClaimValue);
                    }
                }
                return localClaimValues;
            } else {
                for (org.wso2.carbon.user.api.ClaimMapping claimMapping : mappings) {
                    localClaimUri = claimMapping.getClaim().getClaimUri();
                    localClaimValue = claimsMap.get(localClaimUri);
                    remoteClaimUri = claimMapping.getMappedAttribute();
                    if (localClaimValue != null && mappedClaims.contains(localClaimUri)) {
                        requestedClaim.put(remoteClaimUri, localClaimValue);
                    }
                }
                if (requestedClaim.isEmpty()) {
                    claimsMap.remove(CASConstants.MULTI_ATTRIBUTE_SEPARATOR);
                    return claimsMap;
                } else {
                    return requestedClaim;
                }
            }
        } catch (UserStoreException e) {
            log.info("Error while retrieving claims values", e);
            throw new CASIdentityException("Error while retrieving claims values", e);
        } catch (CarbonException | org.wso2.carbon.user.api.UserStoreException e) {
            log.info("Error while retrieving claims values", e);
            throw new CASIdentityException("Error while retrieving claim values", e);
        }
    }


    public static String buildAttributesXml(AuthenticationResult result, ClaimMapping[] claimMapping)
            throws IdentityException {
        StringBuilder attributesXml = new StringBuilder();
        Map<String, String> claims = CASSSOUtil.getUserClaimValues(result, claimMapping, null);
        for (Map.Entry<String, String> entry : claims.entrySet()) {
            String entryKey = entry.getKey().replaceAll(" ", "_");
            attributesXml.append(String.format(attributeTemplate, entryKey, entry.getValue(), entryKey));
        }
        if (log.isDebugEnabled()) {
            log.debug("attributesXml:\n" + attributesXml);
        }
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