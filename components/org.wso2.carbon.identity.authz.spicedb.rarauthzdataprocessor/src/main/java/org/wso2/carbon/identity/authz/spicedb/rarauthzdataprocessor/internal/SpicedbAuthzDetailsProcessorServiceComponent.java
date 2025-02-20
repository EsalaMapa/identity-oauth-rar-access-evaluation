package org.wso2.carbon.identity.authz.spicedb.rarauthzdataprocessor.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.wso2.carbon.identity.authz.spicedb.rarauthzdataprocessor.SpicedbAuthzDetailsProcessor;
import org.wso2.carbon.identity.oauth2.rar.core.AuthorizationDetailsProcessor;

/**
 * Service component to register the RAR authorization details processor for spiceDB.
 */
@Component(
        name = "identity.authz.spicedb.authzdataprocessor.component",
        immediate = true
)
public class SpicedbAuthzDetailsProcessorServiceComponent {

    private static final Log LOG = LogFactory.getLog(SpicedbAuthzDetailsProcessorServiceComponent.class);

    /**
     * Method to activate the component.
     *
     * @param context Context of the component
     */
    @Activate
    protected void activate (ComponentContext context) {

        try {
            SpicedbAuthzDetailsProcessor spicedbAuthzDetailsProcessor = new SpicedbAuthzDetailsProcessor();
            BundleContext bundleContext = context.getBundleContext();
            bundleContext.registerService(AuthorizationDetailsProcessor.class, spicedbAuthzDetailsProcessor, null);
            LOG.debug("RAR authorization details processor for spiceDB bundle is activated");
        } catch (Throwable throwable) {
            LOG.error("Error while starting RAR authorization details processor for spiceDB component", throwable);
        }
    }

    /**
     * Method to deactivate the component.
     *
     * @param context Context of the component
     */
    @Deactivate
    protected void deactivate (ComponentContext context) {

        LOG.debug("RAR authorization details processor for spiceDB bundle is deactivated.");
    }
}

