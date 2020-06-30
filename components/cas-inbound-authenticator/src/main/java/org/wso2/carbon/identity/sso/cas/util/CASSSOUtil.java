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

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.osgi.service.http.HttpService;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationResult;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationRequestConfig;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.sso.cas.cache.ServiceTicketCache;
import org.wso2.carbon.identity.sso.cas.cache.ServiceTicketCacheEntry;
import org.wso2.carbon.identity.sso.cas.cache.ServiceTicketCacheKey;
import org.wso2.carbon.identity.sso.cas.cache.TicketGrantingTicketCache;
import org.wso2.carbon.identity.sso.cas.cache.TicketGrantingTicketCacheEntry;
import org.wso2.carbon.identity.sso.cas.cache.TicketGrantingTicketCacheKey;
import org.wso2.carbon.identity.sso.cas.constants.CASConstants;
import org.wso2.carbon.identity.sso.cas.exception.CAS2ClientException;
import org.wso2.carbon.identity.sso.cas.exception.CASIdentityException;
import org.wso2.carbon.identity.sso.cas.exception.TicketNotFoundException;
import org.wso2.carbon.identity.sso.cas.ticket.ServiceTicket;
import org.wso2.carbon.identity.sso.cas.ticket.TicketGrantingTicket;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.ConfigurationContextService;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;


public class CASSSOUtil {
    protected static final String validationResponse = "<cas:serviceResponse xmlns:cas=\"http://www.yale.edu/tp/cas\">%s</cas:serviceResponse>";
    private static final String success = "<cas:authenticationSuccess>%s</cas:authenticationSuccess>";
    private static final String userTemplate = "<cas:user>%s</cas:user>";
    private static final String attributesWrapper = "<cas:attributes>%s</cas:attributes>";
    private static final String attributeTemplate = "<cas:%s>%s</cas:%s>";
    private static final Log log = LogFactory.getLog(CASSSOUtil.class);
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

    /**
     * The service provider is registered by either the serviceProviderUrl from request or by a portion of it. Since
     * the portion is not known beforehand, we search for an SP by the base URL extracted from the serviceProviderUrl.
     * If an SP is not found, we add one path component at a time and search for an SP.
     *
     * @param serviceProviderUrl    Service provider URL from request.
     * @param tenantDomain          Tenant Domain.
     * @return                      Service provider if found, default Service Provider if not found.
     * @throws CASIdentityException CAS Identity Exception.
     */
    public static ServiceProvider getServiceProviderByUrl(String serviceProviderUrl, String tenantDomain) throws
            CASIdentityException {

        ServiceProvider serviceProvider = null;
        ApplicationManagementService appInfo = ApplicationManagementService.getInstance();
        if (log.isDebugEnabled()) {
            log.debug("Trying to get service provider using service URL in the request : " + serviceProviderUrl);
        }
        String serviceUrlToSearch = getBaseUrl(serviceProviderUrl);
        try {
            if (tenantDomain == null) {
                tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
            }
            serviceProvider = appInfo.getServiceProviderByClientId(serviceUrlToSearch,
                    CASConstants.CAS_CONFIG_NAME, tenantDomain);
            /*
            If returned SP is the default SP, it means an SP for the searched service URL is not found.
            Hence we incrementally append path variables to the URL one by one and search an SP by that URL.
             */
            if (StringUtils.equals(serviceProvider.getApplicationName(), CASConstants.DEFAULT_SP_CONFIG)) {
                String[] pathSegments = getUrlPathSegments(serviceProviderUrl);
                if (ArrayUtils.isNotEmpty(pathSegments)) {
                    // The number of incremental searches need to be done is defined as a constant.
                    int pathSegmentsToConsiderForSearching = CASConstants.PATH_SEGMENTS_COUNT_FOR_SEARCH;
                    if (CASConstants.PATH_SEGMENTS_COUNT_FOR_SEARCH > pathSegments.length) {
                        pathSegmentsToConsiderForSearching = pathSegments.length;
                    }
                    int pathSegmentCount = 0;
                    while (pathSegmentCount < pathSegmentsToConsiderForSearching &&
                            StringUtils.equals(serviceProvider.getApplicationName(), CASConstants.DEFAULT_SP_CONFIG)) {
                        // First append a '/' and search by that URL. Then append the path component and search again.
                        serviceUrlToSearch = serviceUrlToSearch + "/";
                        serviceProvider = appInfo.getServiceProviderByClientId(serviceUrlToSearch,
                                CASConstants.CAS_CONFIG_NAME, tenantDomain);
                        if (!StringUtils.equals(serviceProvider.getApplicationName(), CASConstants.DEFAULT_SP_CONFIG)) {
                            break;
                        }
                        serviceUrlToSearch = serviceUrlToSearch + pathSegments[pathSegmentCount];
                        serviceProvider = appInfo.getServiceProviderByClientId(serviceUrlToSearch,
                                CASConstants.CAS_CONFIG_NAME, tenantDomain);
                        pathSegmentCount++;
                    }
                    // If the correct SP is not yet found, we finally append a '/' and search again.
                    if (StringUtils.equals(serviceProvider.getApplicationName(), CASConstants.DEFAULT_SP_CONFIG)) {
                        serviceProvider = appInfo.getServiceProviderByClientId(serviceUrlToSearch + "/",
                                CASConstants.CAS_CONFIG_NAME, tenantDomain);
                    }
                }
            }
        } catch (IdentityApplicationManagementException e) {
            throw new CASIdentityException("Error occurred while getting service provider in the tenant domain" +
                    tenantDomain + "'", e);
        }
        if (log.isDebugEnabled()) {
            log.debug("Service provider retrieved for URL : " + serviceProviderUrl + " is " +
                    serviceProvider.getApplicationName());
        }
        return serviceProvider;
    }

    private static String getBaseUrl(String serviceProviderUrl) throws CASIdentityException {

        URL url = null;
        try {
            url = new URL(serviceProviderUrl);
        } catch (MalformedURLException mfe) {
            throw new CASIdentityException("Error occurred while retrieving base url from: " + serviceProviderUrl, mfe);
        }
        String baseUrl = url.getProtocol() + "://" + url.getHost();
        if (url.getPort() != -1) {
            baseUrl = baseUrl + ":" + url.getPort();
        }
        return baseUrl;
    }

    /**
     * Return an array of path variables extracted from the service URL.
     *
     * @param serviceProviderUrl    Service URL from the request.
     * @return                      Array of path variables.
     * @throws CASIdentityException CAS Identity Exception.
     */
    private static String[] getUrlPathSegments(String serviceProviderUrl) throws CASIdentityException {

        URL url = null;
        try {
            url = new URL(serviceProviderUrl);
        } catch (MalformedURLException mfe) {
            throw new CASIdentityException("Error occurred while retrieving path segments from url: " +
                    serviceProviderUrl, mfe);
        }
        String pathComponent = url.getPath();
        if (StringUtils.isEmpty(pathComponent)) {
            return new String[0];
        }
        // Path will always have a leading '/' character. Hence we should remove that and split using intermediate '/'s.
        return pathComponent.substring(1).split("/");
    }

    public static String getAcsUrl(String serviceProviderUrl, String tenantDomain) throws CAS2ClientException {
        ServiceProvider serviceProvider;
        String acsUrl = null;

        try {
            serviceProvider = getServiceProviderByUrl(serviceProviderUrl, tenantDomain);
            for (InboundAuthenticationRequestConfig authenticationRequestConfig : serviceProvider
                    .getInboundAuthenticationConfig().getInboundAuthenticationRequestConfigs()) {
                if (StringUtils.equals(authenticationRequestConfig.getInboundAuthType(),
                        CASConstants.CAS_CONFIG_NAME)) {
                    acsUrl = authenticationRequestConfig.getInboundAuthKey();
                    break;
                }
            }
        } catch (CASIdentityException e) {
            throw CAS2ClientException.error("Error while getting acsUrl from Inbound configuration", e);
        }
        return acsUrl;
    }

    /**
     * Checks whether the service URL in service ticket matches the registered service URL.
     *
     * @param registeredAcsUrl  Service URL in the CAS inbound authentication configuration.
     * @param serviceTicketId   Service ticket ID.
     * @return                  True if registeredAcsUrl matches service URL in the service ticket.
     */
    public static boolean isValidAcsUrlForServiceTicket(String registeredAcsUrl, String serviceTicketId) {

        String acsUrlInServiceTicket = CASSSOUtil.getServiceTicket(serviceTicketId).getService();
        boolean isValidAcsUrl = false;
        if (acsUrlInServiceTicket.equals(registeredAcsUrl)) {
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

    /**
     * @param result        the authentication result.
     * @param claimMappings the claim mappings.
     * @param profile       the profile.
     * @return requestedClaims map.
     * @throws IdentityException
     */

    public static Map<String, String> getUserClaimValues(AuthenticationResult result, ClaimMapping[] claimMappings,
                                                         String profile) throws IdentityException {
        Map<String, String> requestedClaims = new HashMap<String, String>();
        if (result != null && result.getSubject() != null) {
            if (log.isDebugEnabled()) {
                log.debug("Trying to get userAttributes with Authentication Result " + result + " for user " + result
                        .getSubject());
            }
            Map<ClaimMapping, String> userAttributes = result.getSubject().getUserAttributes();
            if (userAttributes != null) {
                if (log.isDebugEnabled()) {
                    log.debug("Getting the userAttributes from authentication results user attributes");
                }
                for (Map.Entry<ClaimMapping, String> entry : userAttributes.entrySet()) {
                    if (log.isDebugEnabled()) {
                        log.debug(entry.getKey().getLocalClaim().getClaimUri() + " ==> " + entry.getValue());
                    }
                    if (!entry.getKey().getLocalClaim().getClaimUri().equals(IdentityCoreConstants
                            .MULTI_ATTRIBUTE_SEPARATOR)) {
                        requestedClaims.put(entry.getKey().getLocalClaim().getClaimUri(), entry.getValue());
                    }
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("User attributes not found in AuthenticatedUser. Hence returning empty map.");
                }
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Either authentication result null or authenticated user is not present. Hence user " +
                        "returning empty map for user attributes ");
            }
        }
        return requestedClaims;
    }

    /**
     * @param result       the authentication result.
     * @param claimMapping the claim mappings.
     * @return attributesXml.
     * @throws IdentityException
     */

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