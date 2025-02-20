package org.wso2.carbon.identity.authz.spicedb.rarauthzdataprocessor;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONObject;
import org.wso2.carbon.identity.oauth.rar.exception.AuthorizationDetailsProcessingException;
import org.wso2.carbon.identity.oauth.rar.model.AuthorizationDetail;
import org.wso2.carbon.identity.oauth.rar.model.AuthorizationDetails;
import org.wso2.carbon.identity.oauth.rar.model.ValidationResult;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ServerException;
import org.wso2.carbon.identity.oauth2.fga.FGAuthorizationException;
import org.wso2.carbon.identity.oauth2.fga.factory.FGAuthorizationEngineFactory;
import org.wso2.carbon.identity.oauth2.fga.models.AuthzCheckRequest;
import org.wso2.carbon.identity.oauth2.fga.models.AuthzCheckResponse;
import org.wso2.carbon.identity.oauth2.fga.services.FGAuthorizationInterface;
import org.wso2.carbon.identity.oauth2.rar.core.AuthorizationDetailsProcessor;
import org.wso2.carbon.identity.oauth2.rar.model.AuthorizationDetailsContext;

import java.util.Map;

/**
 *
 */
public class SpicedbAuthzDetailsProcessor implements AuthorizationDetailsProcessor {

    private static final Log LOG = LogFactory.getLog(SpicedbAuthzDetailsProcessor.class);
    private FGAuthorizationInterface authorizationService;

    @Override
    public ValidationResult validate(AuthorizationDetailsContext authorizationDetailsContext)
            throws AuthorizationDetailsProcessingException, IdentityOAuth2ServerException {

        try {
            authorizationService = FGAuthorizationEngineFactory.createServiceInstance().getAuthorizationService();
        } catch (Exception e) {
            throw new IdentityOAuth2ServerException(e.getMessage(), e);
        }
        AuthzCheckRequest authzCheckRequest = createCheckRequest
                (authorizationDetailsContext.getAuthorizationDetail().getDetails());
        AuthzCheckResponse authzCheckResponse;
        try {
            authzCheckResponse = authorizationService.checkAuthorization(authzCheckRequest);
        } catch (FGAuthorizationException e) {
            throw new IdentityOAuth2ServerException(e.getMessage(), e);
        }
        if (authzCheckResponse.isAuthorized()) {
            return new ValidationResult(true, "Authorized", null);
        } else {
            return new ValidationResult(false, "Not Authorized", null);
        }
    }

    @Override
    public String getType() {

        return "fga_request";
    }

    @Override
    public boolean isEqualOrSubset(AuthorizationDetail requestedAuthorizationDetail,
                                   AuthorizationDetails existingAuthorizationDetails) {

        return false;
    }

    @Override
    public AuthorizationDetail enrich(AuthorizationDetailsContext authorizationDetailsContext) {

        return null;
    }

    private AuthzCheckRequest createCheckRequest(Map<String, Object> authzDetails) {

        JSONObject resource = (JSONObject) authzDetails.get("resource");
        JSONObject subject = (JSONObject) authzDetails.get("subject");
        String resourceType = resource.getString("resourceType");
        String resourceId = resource.getString("resourceId");
        String action = (String) authzDetails.get("action");
        String subjectType = subject.getString("subjectType");
        String subjectId = subject.getString("subjectId");

        return new AuthzCheckRequest(resourceType, resourceId, action, subjectType, subjectId);
    }
}
