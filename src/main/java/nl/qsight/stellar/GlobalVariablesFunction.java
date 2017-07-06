package nl.qsight.stellar;

import org.apache.log4j.Logger;
import org.apache.metron.common.dsl.*;

import java.util.*;

public class GlobalVariablesFunction {

    private static Logger LOG = Logger.getLogger(GlobalVariablesFunction.class);
    private static Set<String> extractFields;
    private static final String EXTRACT_FIELDS_KEY = "sep.whitelist.extract.fields";
    /**
     * Stellar Function: GET_GLOBAL_VAR
     * <p>
     * Return the value of a key on Metrons Global Variables.
     */
    @Stellar(name = "GET_GLOBAL_VAR"
            , description = "Return the value of a key on Metrons Global Variables."
            , params = {"key - The key of the variable to return"}
            , returns = "The value as String")
    public static class GetGlobalVariable implements StellarFunction {

        boolean initialized = false;
        Map<String, Object> globalConfig;

        @Override
        public Object apply(List<Object> args, Context context) throws ParseException {

            if(!initialized) {
                return null;
            }

            if (args.size()<1) {
                throw new IllegalStateException("Requires at least a key (String) of the variable to get");
            }

            String key = (String) args.get(0);

            return (String) globalConfig.get(key);

        }

        @Override
        public void initialize(Context context) {

            globalConfig = (Map<String, Object>) context.getCapability(Context.Capabilities.GLOBAL_CONFIG, false).orElse(new HashMap<>());
            LOG.info("Initializing GetGlobalVariable Function. GLOBAL_CONFIG has ["+globalConfig.size()+"] values");
            initialized = true;
        }

        @Override
        public boolean isInitialized() {
            return initialized;
        }
    }
}