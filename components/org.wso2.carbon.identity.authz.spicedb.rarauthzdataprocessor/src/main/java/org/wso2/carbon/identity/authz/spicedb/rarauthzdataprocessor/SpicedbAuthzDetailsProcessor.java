/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.authz.spicedb.rarauthzdataprocessor;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONArray;
import org.json.JSONObject;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.oauth.rar.exception.AuthorizationDetailsProcessingException;
import org.wso2.carbon.identity.oauth.rar.model.AuthorizationDetail;
import org.wso2.carbon.identity.oauth.rar.model.AuthorizationDetails;
import org.wso2.carbon.identity.oauth.rar.model.ValidationResult;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ServerException;
import org.wso2.carbon.identity.oauth2.fga.FGAuthorizationException;
import org.wso2.carbon.identity.oauth2.fga.factory.FGAuthorizationEngineFactory;
import org.wso2.carbon.identity.oauth2.fga.models.AuthzActionObject;
import org.wso2.carbon.identity.oauth2.fga.models.AuthzBulkCheckRequest;
import org.wso2.carbon.identity.oauth2.fga.models.AuthzBulkCheckResponse;
import org.wso2.carbon.identity.oauth2.fga.models.AuthzCheckRequest;
import org.wso2.carbon.identity.oauth2.fga.models.AuthzCheckResponse;
import org.wso2.carbon.identity.oauth2.fga.models.AuthzResourceObject;
import org.wso2.carbon.identity.oauth2.fga.models.AuthzSubjectObject;
import org.wso2.carbon.identity.oauth2.fga.models.ErrorResponse;
import org.wso2.carbon.identity.oauth2.fga.models.ListObjectsRequest;
import org.wso2.carbon.identity.oauth2.fga.models.ListObjectsResponse;
import org.wso2.carbon.identity.oauth2.fga.models.ListObjectsResult;
import org.wso2.carbon.identity.oauth2.fga.services.FGAuthorizationInterface;
import org.wso2.carbon.identity.oauth2.rar.core.AuthorizationDetailsProcessor;
import org.wso2.carbon.identity.oauth2.rar.model.AuthorizationDetailsContext;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 *
 */
public class SpicedbAuthzDetailsProcessor implements AuthorizationDetailsProcessor {

    private static final Log LOG = LogFactory.getLog(SpicedbAuthzDetailsProcessor.class);

    private JSONArray authzRequests;
    private int requestType;
    private AuthzCheckResponse authzCheckResponse;
    private AuthzBulkCheckResponse authzBulkCheckResponse;
    private ListObjectsResponse listObjectsResponse;
    private ArrayList<AuthzCheckRequest> authzCheckRequests;

    private static final int CHECK_REQUEST = 1;
    private static final int LIST_REQUEST = 2;
    private static final int BATCH_REQUEST = 3;

    @Override
    public ValidationResult validate(AuthorizationDetailsContext authorizationDetailsContext)
            throws AuthorizationDetailsProcessingException, IdentityOAuth2ServerException {

        FGAuthorizationInterface authorizationService;
        try {
            authorizationService = FGAuthorizationEngineFactory.createServiceInstance().getAuthorizationService();
        } catch (Exception e) {
            throw new IdentityOAuth2ServerException(e.getMessage(), e);
        }
        JSONObject authzDetailsObject = new JSONObject(authorizationDetailsContext.
                getAuthorizationDetail().getDetails());
        authzRequests = authzDetailsObject.getJSONArray("requests");
        String userId;
        try {
            userId = authorizationDetailsContext.getAuthenticatedUser().getUserId();
        } catch (UserIdNotFoundException e) {
            throw new IdentityOAuth2ServerException(e.getMessage(), e);
        }
        setRequestType();
        switch (requestType) {
            case CHECK_REQUEST:
                AuthzCheckRequest authzCheckRequest = createCheckRequest(authzRequests.getJSONObject(0), userId);
                try {
                    this.authzCheckResponse = authorizationService.checkAuthorization(authzCheckRequest);
                } catch (FGAuthorizationException e) {
                    throw new IdentityOAuth2ServerException(e.getMessage(), e);
                }
                return new ValidationResult(true, "Fine-grained Authorization performed Successfully.", null);
            case LIST_REQUEST:
                ListObjectsRequest listObjectsRequest = createListObjectsRequest(userId);
                try {
                    this.listObjectsResponse = authorizationService.lookUpResources(listObjectsRequest);
                } catch (FGAuthorizationException e) {
                    throw new IdentityOAuth2ServerException(e.getMessage(), e);
                }
                return new ValidationResult(true, "Fine-grained Authorization performed Successfully.", null);
            case BATCH_REQUEST:
                AuthzBulkCheckRequest authzBulkCheckRequest = createBulkCheckRequest(userId);
                try {
                    this.authzBulkCheckResponse = authorizationService.bulkCheckAuthorization(authzBulkCheckRequest);
                } catch (FGAuthorizationException e) {
                    throw new IdentityOAuth2ServerException(e.getMessage(), e);
                }
                return new ValidationResult(true, "Fine-grained Authorization performed Successfully.", null);
            default:
                return new ValidationResult
                        (false, "Fine-grained Authorization failed. Couldn't recognize request type.", null);
        }
    }

    @Override
    public String getType() {

        return "access_evaluation_request";
    }

    @Override
    public boolean isEqualOrSubset(AuthorizationDetail requestedAuthorizationDetail,
                                   AuthorizationDetails existingAuthorizationDetails) {

        return false;
    }

    @Override
    public AuthorizationDetail enrich(AuthorizationDetailsContext authorizationDetailsContext) {

        switch (requestType) {
            case CHECK_REQUEST:
                if (authzCheckResponse != null) {
                    JSONObject resultContext = new JSONObject();
                    if (authzCheckResponse.isAuthorized()) {
                        resultContext.put("authorized", authzCheckResponse.isAuthorized());
                        authzRequests.getJSONObject(0).append("result", resultContext);
                    } else {
                        resultContext.put("authorized", authzCheckResponse.isAuthorized());
                        resultContext.put("additionalContext", authzCheckResponse.getAdditionalContext());
                        authzRequests.getJSONObject(0).append("result", resultContext);
                    }
                }
                return modifyAuthzRequests(authorizationDetailsContext);
            case LIST_REQUEST:
                List<Map<String, Object>> results = new ArrayList<>();
                List<Map<String, Object>> errorResults = new ArrayList<>();
                if (listObjectsResponse != null) {
                    for (ListObjectsResult result : listObjectsResponse.getResults()) {
                        Map<String, Object> resultObject = new HashMap<>();
                        resultObject.put("resourceId", result.getResultObjectId());
                        resultObject.put("additionalContext", result.getAdditionalContext());
                        results.add(resultObject);
                    }
                    for (ErrorResponse error : listObjectsResponse.getErrorResults()) {
                        Map<String, Object> errorObject = new HashMap<>();
                        errorObject.put("error", parseErrorToJSON(error));
                        errorResults.add(errorObject);
                    }
                }
                if (!results.isEmpty()) {
                    authzRequests.getJSONObject(0).getJSONObject("resource").put("results", results);
                } else if (!errorResults.isEmpty()) {
                    authzRequests.getJSONObject(0).getJSONObject("resource").put("errorResults", errorResults);
                }
                return modifyAuthzRequests(authorizationDetailsContext);
            case BATCH_REQUEST:
                if (authzBulkCheckResponse != null) {
                    HashMap<AuthzCheckRequest, AuthzCheckResponse> responses = authzBulkCheckResponse.getResults();
                    HashMap<AuthzCheckRequest, ErrorResponse> errorResponses = authzBulkCheckResponse.getErrorResults();
                    for (int i = 0; i < authzCheckRequests.size(); i++) {
                        AuthzCheckRequest requestObj = authzCheckRequests.get(i);
                        boolean containsKey = responses.containsKey(requestObj);
                        if (containsKey) {
                            AuthzCheckResponse response = responses.get(requestObj);
                            JSONObject resultContext = new JSONObject();
                            resultContext.put("authorized", response.isAuthorized());
                            resultContext.put("resultContext", response.getAdditionalContext());
                            authzRequests.getJSONObject(i).put("result", resultContext);
                        } else if (errorResponses.containsKey(requestObj)) {
                            ErrorResponse errorResponse = errorResponses.get(requestObj);
                            authzRequests.getJSONObject(i).put("error", parseErrorToJSON(errorResponse));
                        }
                    }
                }
                return modifyAuthzRequests(authorizationDetailsContext);
            default:
                return authorizationDetailsContext.getAuthorizationDetail();
        }
    }

    private AuthorizationDetail modifyAuthzRequests(AuthorizationDetailsContext authorizationDetailsContext) {

        Map<String, Object> details = authorizationDetailsContext.getAuthorizationDetail().getDetails();
        List<Object> requestsList = authzRequests.toList();
        details.replace("requests", requestsList);
        authorizationDetailsContext.getAuthorizationDetail().setDetails(details);
        return authorizationDetailsContext.getAuthorizationDetail();
    }

    private AuthzCheckRequest createCheckRequest(JSONObject requestObject, String userId) {

        if (requestObject != null && !requestObject.isEmpty()) {
            JSONObject resource = requestObject.getJSONObject("resource");
            String resourceType = resource.getString("resourceType");
            String resourceId;
            if (resource.has("resourceId")) {
                resourceId = resource.getString("resourceId");
            } else {
                throw new IllegalArgumentException("Resource Id cannot be empty in a check request");
            }
            String action = requestObject.getJSONObject("action").getString("name");
            String subjectType = "user";
            AuthzSubjectObject subjectObject = new AuthzSubjectObject(subjectType, userId);
            AuthzActionObject actionObject = new AuthzActionObject(action);
            AuthzResourceObject resourceObject = new AuthzResourceObject(resourceType, resourceId);
            return new AuthzCheckRequest(subjectObject, actionObject, resourceObject);
        } else {
            throw new IllegalArgumentException("Authorization details cannot be empty.");
        }
    }

    private ListObjectsRequest createListObjectsRequest(String userId) {

        if (authzRequests != null && !authzRequests.isEmpty()) {
            JSONObject requestObject = authzRequests.getJSONObject(0);
            JSONObject resource = requestObject.getJSONObject("resource");
            String resourceType = resource.getString("resourceType");
            String subjectType = "user";
            String relation = requestObject.getJSONObject("action").getString("name");
            return new ListObjectsRequest(resourceType, relation, subjectType, userId);
        } else {
            throw new IllegalArgumentException("Authorization details cannot be empty.");
        }
    }


    private AuthzBulkCheckRequest createBulkCheckRequest(String userId) {

        authzCheckRequests = new ArrayList<>();
        for (Object request : authzRequests) {
            AuthzCheckRequest checkRequest = createCheckRequest((JSONObject) request, userId);
            authzCheckRequests.add(checkRequest);
        }
        return new AuthzBulkCheckRequest(authzCheckRequests);
    }

    private void setRequestType() {

        if (authzRequests.length() == 1) {
            if (authzRequests.getJSONObject(0).getJSONObject("resource").has("resourceId")) {
                this.requestType = CHECK_REQUEST;
            } else {
                this.requestType = LIST_REQUEST;
            }
        } else {
            this.requestType = BATCH_REQUEST;
        }
    }

    private JSONObject parseErrorToJSON (ErrorResponse error) {
        JSONObject errorObject = new JSONObject();
        errorObject.put("error", new JSONObject().put("code", error.getErrorCode())
                .append("message", error.getErrorMessage())
                .append("details", error.getErrorDetails()));
        return errorObject;
    }
}
