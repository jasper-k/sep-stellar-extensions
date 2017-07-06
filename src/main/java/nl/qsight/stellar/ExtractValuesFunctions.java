package nl.qsight.stellar;

import org.apache.log4j.Logger;
import org.apache.metron.common.dsl.*;

import java.util.*;
import java.util.regex.Pattern;

public class ExtractValuesFunctions {

    private static Logger LOG = Logger.getLogger(ExtractValuesFunctions.class);
    private static Set<String> extractFields;
    private static final String EXTRACT_FIELDS_KEY = "sep.whitelist.extract.fields";

   @Stellar( name="LIST_OF_FIELDS_AND_KEYS_TO_MAP"
            , description="Joins the components in the list of strings with the specified delimiter. The components are meant" +
            " to point to message variables"
            , params = { "list - List of fields", "delim - String delimiter"}
            , returns = "String"
    )
    public static class ListFieldsAndKeysToMapFunction implements StellarFunction {

        boolean initialized = false;

        @Override
        public Object apply(List<Object> args, Context context) {
            List<Object> arg1 = (List<Object>) args.get(0);
            Map<String,String> outMap = new HashMap<>();

            Map<String,String> incrMap = new HashMap<>();
            String key = null;

            for (Object obj : arg1) {
                String value = null;
                if (extractFields.contains(obj)) {
                    key = obj.toString();
                }
                else {
                    value = obj.toString();
                    outMap.put(key, value);
                }
            }
            return outMap;
        }

        @Override
        public void initialize(Context context) {
            LOG.info("Initializing ExtractValue Function");
            Map<String, Object> config = getConfig(context);

            if (config.containsKey(EXTRACT_FIELDS_KEY)) {
                String fields = (String) config.get(EXTRACT_FIELDS_KEY);

                LOG.info("Found global config key ["+EXTRACT_FIELDS_KEY+"] with value : ["+fields+"]");
                extractFields = new HashSet<>(Arrays.asList(fields.split(Pattern.quote(","))));
            }
            else {
                extractFields = new HashSet<>();
            }
            initialized = true;
        }

        private static Map<String, Object> getConfig(Context context) {
            return (Map<String, Object>) context.getCapability(Context.Capabilities.GLOBAL_CONFIG, false).orElse(new HashMap<>());
        }

        @Override
        public boolean isInitialized() {
            return initialized;
        }
    }

    @Stellar( name="REBUILD_ARGS"
            , description="Joins the components in the list of strings with the specified delimiter. The components are meant" +
            " to point to message variables"
            , params = { "list - List of fields", "delim - String delimiter"}
            , returns = "String"
    )
    public static class RebuildArgumentListFunction extends BaseStellarFunction {
        @Override
        public Object apply(List<Object> args) {
            List<Object> arg1 = Arrays.asList(((String) args.get(0)).split(","));

            StringBuilder sb = new StringBuilder();
            for (Object obj : arg1) {
                sb.append("'")
                        .append(obj)
                        .append("',")
                        .append(obj)
                        .append(",");
            }
            sb.deleteCharAt(sb.length()-1);
            return sb.toString();
        }
    }

}