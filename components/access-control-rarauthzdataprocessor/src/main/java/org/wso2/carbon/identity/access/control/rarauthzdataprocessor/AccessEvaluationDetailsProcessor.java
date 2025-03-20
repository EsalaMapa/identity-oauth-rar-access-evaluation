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

package org.wso2.carbon.identity.access.control.rarauthzdataprocessor;

import org.json.JSONArray;
import org.json.JSONObject;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.authorization.framework.exception.AccessEvaluationException;
import org.wso2.carbon.identity.authorization.framework.factory.AccessEvaluationFactory;
import org.wso2.carbon.identity.authorization.framework.model.AccessEvaluationRequest;
import org.wso2.carbon.identity.authorization.framework.model.AccessEvaluationResponse;
import org.wso2.carbon.identity.authorization.framework.model.AuthorizationAction;
import org.wso2.carbon.identity.authorization.framework.model.AuthorizationResource;
import org.wso2.carbon.identity.authorization.framework.model.AuthorizationSubject;
import org.wso2.carbon.identity.authorization.framework.model.BulkAccessEvaluationRequest;
import org.wso2.carbon.identity.authorization.framework.model.BulkAccessEvaluationResponse;
import org.wso2.carbon.identity.authorization.framework.model.SearchObjectsRequest;
import org.wso2.carbon.identity.authorization.framework.model.SearchObjectsResponse;
import org.wso2.carbon.identity.authorization.framework.model.SearchObjectsResult;
import org.wso2.carbon.identity.authorization.framework.service.AccessEvaluationService;
import org.wso2.carbon.identity.oauth.rar.exception.AuthorizationDetailsProcessingException;
import org.wso2.carbon.identity.oauth.rar.model.AuthorizationDetail;
import org.wso2.carbon.identity.oauth.rar.model.AuthorizationDetails;
import org.wso2.carbon.identity.oauth.rar.model.ValidationResult;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ServerException;
import org.wso2.carbon.identity.oauth2.rar.core.AuthorizationDetailsProcessor;
import org.wso2.carbon.identity.oauth2.rar.model.AuthorizationDetailsContext;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * The {@code AccessEvaluationDetailsProcessor} class is an implementation of the {@link AuthorizationDetailsProcessor}
 * interface. This class is used to process the authorization details that are retrieved from a Rich Authorization
 * Request to perform Access Evaluation with a connected Authorization Engine. This class would validate and enrich
 * authorization details that has the type {@code access_evaluation_request}.
 */
public class AccessEvaluationDetailsProcessor implements AuthorizationDetailsProcessor {

    private JSONArray authzRequests;
    private int requestType;
    private AccessEvaluationResponse authzCheckResponse;
    private BulkAccessEvaluationResponse authzBulkCheckResponse;
    private SearchObjectsResponse listObjectsResponse;
    private ArrayList<AccessEvaluationRequest> authzCheckRequests;

    private static final int CHECK_REQUEST = 1;
    private static final int LIST_REQUEST = 2;
    private static final int BATCH_REQUEST = 3;

    /**
     * Validates the provided authorization details context when a new Rich Authorization Request is received.
     * <p>
     *     This method validates the authorization details context by using the details provided in the context to
     *     perform access evaluation with a connected Authorization Engine. The validation fails only if the request
     *     type is not recognized.
     * </p>
     * @see AuthorizationDetailsProcessor#validate(AuthorizationDetailsContext)
     */
    @Override
    public ValidationResult validate(AuthorizationDetailsContext authorizationDetailsContext)
            throws AuthorizationDetailsProcessingException, IdentityOAuth2ServerException {

        AccessEvaluationService accessEvaluationService;
        try {
            accessEvaluationService = AccessEvaluationFactory.getInstance()
                    .createServiceInstanceByName("Topaz").getAccessEvaluationService();
        } catch (AccessEvaluationException e) {
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
                AccessEvaluationRequest accessEvaluationRequest = createEvaluationRequest(
                        authzRequests.getJSONObject(0), userId);
                try {
                    this.authzCheckResponse = accessEvaluationService.evaluate(accessEvaluationRequest);
                } catch (AccessEvaluationException e) {
                    throw new IdentityOAuth2ServerException(e.getMessage(), e);
                }
                return new ValidationResult(true, "Access Evaluation performed Successfully.", null);
            case LIST_REQUEST:
                SearchObjectsRequest searchObjectsRequest = createSearchObjectsRequest(userId);
                try {
                    this.listObjectsResponse = accessEvaluationService.searchObjectsRequest(searchObjectsRequest);
                } catch (AccessEvaluationException e) {
                    throw new IdentityOAuth2ServerException(e.getMessage(), e);
                }
                return new ValidationResult(true, "Access Evaluation performed Successfully.", null);
            case BATCH_REQUEST:
                BulkAccessEvaluationRequest bulkAccessEvaluationRequest = createBulkEvaluationRequest(userId);
                try {
                    this.authzBulkCheckResponse = accessEvaluationService.bulkEvaluate(bulkAccessEvaluationRequest);
                } catch (AccessEvaluationException e) {
                    throw new IdentityOAuth2ServerException(e.getMessage(), e);
                }
                return new ValidationResult(true, "Access Evaluation performed Successfully.", null);
            default:
                return new ValidationResult
                        (false, "Access Evaluation failed. Couldn't recognize request type.", null);
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

    /**
     * Enriches the provided authorization details context with the results of the access evaluation.
     * <p>
     *     This method enriches the authorization details context with the results of the access evaluation performed
     *     with the connected Authorization Engine. The results are added to the context as a new key-value pair.
     * </p>
     * @see AuthorizationDetailsProcessor#enrich(AuthorizationDetailsContext)
     */
    @Override
    public AuthorizationDetail enrich(AuthorizationDetailsContext authorizationDetailsContext) {

        switch (requestType) {
            case CHECK_REQUEST:
                if (authzCheckResponse != null) {
                    JSONObject resultContext = new JSONObject();
                    if (authzCheckResponse.getDecision()) {
                        resultContext.put("authorized", authzCheckResponse.getDecision());
                        authzRequests.getJSONObject(0).append("result", resultContext);
                    } else {
                        resultContext.put("authorized", authzCheckResponse.getDecision());
                        resultContext.put("additionalContext", authzCheckResponse.getContext());
                        authzRequests.getJSONObject(0).append("result", resultContext);
                    }
                }
                return modifyAuthzRequests(authorizationDetailsContext);
            case LIST_REQUEST:
                List<Map<String, Object>> results = new ArrayList<>();
                List<Map<String, Object>> errorResults = new ArrayList<>();
                if (listObjectsResponse != null) {
                    for (SearchObjectsResult result : listObjectsResponse.getResults()) {
                        Map<String, Object> resultObject = new HashMap<>();
                        resultObject.put("resourceId", result.getResultObjectId());
                        resultObject.put("additionalContext", result.getContext());
                        results.add(resultObject);
                    }
                }
                if (!results.isEmpty()) {
                    authzRequests.getJSONObject(0).getJSONObject("resource").put("results", results);
                }
                return modifyAuthzRequests(authorizationDetailsContext);
            case BATCH_REQUEST:
                if (authzBulkCheckResponse != null) {
                    List<AccessEvaluationResponse> responses = authzBulkCheckResponse.getResults();
                    for (int i = 0; i < responses.size(); i++) {
                        AccessEvaluationResponse response = responses.get(i);
                            JSONObject resultContext = new JSONObject();
                            resultContext.put("authorized", response.getDecision());
                            resultContext.put("resultContext", response.getContext());
                            authzRequests.getJSONObject(i).put("result", resultContext);
                    }
                }
                return modifyAuthzRequests(authorizationDetailsContext);
            default:
                return authorizationDetailsContext.getAuthorizationDetail();
        }
    }

    /**
     * Modifies the authorization details context with the results of the access evaluation.
     * <p>
     *     This method modifies the authorization details context to add the results of the access evaluation performed
     *     to the context returned.
     * </p>
     * @param authorizationDetailsContext The context containing the authorization details to be modified.
     * @return The modified authorization details context.
     */
    private AuthorizationDetail modifyAuthzRequests(AuthorizationDetailsContext authorizationDetailsContext) {

        Map<String, Object> details = authorizationDetailsContext.getAuthorizationDetail().getDetails();
        List<Object> requestsList = authzRequests.toList();
        details.replace("requests", requestsList);
        authorizationDetailsContext.getAuthorizationDetail().setDetails(details);
        return authorizationDetailsContext.getAuthorizationDetail();
    }

    /**
     * Creates an access evaluation request object from the provided request object and user ID.
     *
     * @param requestObject The request object containing the authorization details.
     * @param userId The user ID of the authenticated user.
     * @return The access evaluation request object.
     */
    private AccessEvaluationRequest createEvaluationRequest(JSONObject requestObject, String userId) {

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
            AuthorizationSubject subjectObject = new AuthorizationSubject(subjectType, userId);
            AuthorizationAction actionObject = new AuthorizationAction(action);
            AuthorizationResource resourceObject = new AuthorizationResource(resourceType, resourceId);
            return new AccessEvaluationRequest(subjectObject, actionObject, resourceObject);
        } else {
            throw new IllegalArgumentException("Authorization details cannot be empty.");
        }
    }

    /**
     * Creates a search objects request object from the provided user ID.
     *
     * @param userId The user ID of the authenticated user.
     * @return The search objects request object.
     */
    private SearchObjectsRequest createSearchObjectsRequest(String userId) {

        if (authzRequests != null && !authzRequests.isEmpty()) {
            JSONObject requestObject = authzRequests.getJSONObject(0);
            JSONObject resource = requestObject.getJSONObject("resource");
            String resourceType = resource.getString("resourceType");
            String subjectType = "user";
            String relation = requestObject.getJSONObject("action").getString("name");
            return new SearchObjectsRequest(resourceType, relation, subjectType, userId);
        } else {
            throw new IllegalArgumentException("Authorization details cannot be empty.");
        }
    }

    /**
     * Creates a bulk access evaluation request object from the provided user ID.
     *
     * @param userId The user ID of the authenticated user.
     * @return The bulk access evaluation request object.
     */
    private BulkAccessEvaluationRequest createBulkEvaluationRequest(String userId) {

        authzCheckRequests = new ArrayList<>();
        for (Object request : authzRequests) {
            AccessEvaluationRequest checkRequest = createEvaluationRequest((JSONObject) request, userId);
            authzCheckRequests.add(checkRequest);
        }
        return new BulkAccessEvaluationRequest(authzCheckRequests);
    }

    /**
     * Sets the request type based on the number of requests in the authorization details.
     */
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
}
