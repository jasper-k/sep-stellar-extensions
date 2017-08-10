package nl.qsight.stellar;

import nl.qsight.stellar.util.WhiteListRule;
import org.apache.log4j.Logger;
import org.apache.metron.stellar.dsl.Context;
import org.apache.metron.stellar.dsl.Stellar;
import org.apache.metron.stellar.dsl.StellarFunction;

import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class ExtractValuesFunctions {

    private static Logger LOG = Logger.getLogger(ExtractValuesFunctions.class);
    private static Set<String> extractFields;
    private static final String EXTRACT_FIELDS_KEY = "sep.whitelist.extract.fields";

   @Stellar( name="LIST_OF_FIELDS_AND_KEYS_TO_MAP"
            , description="Joins the components in the list of strings with the specified delimiter. The components are meant" +
            " to point to message variables"
            , params = { "list - List of variable names and their values (or absent if null)"}
            , returns = "map of variable names and values (of non-null variables only)"
    )
    public static class ListFieldsAndKeysToMapFunction implements StellarFunction {

        boolean initialized = false;

        @Override
        public Object apply(List<Object> args, Context context) {

            if (args.size() != 1) {
                throw new IllegalStateException("Requires at least a list of variable names and variable values");
            }
            List<Object> arg1 = (List<Object>) args.get(0);
            Map<String,String> outMap = new HashMap<>();

            String keyOut = null;
            Boolean isRequiredKey = false;
            Boolean isKey = false;

            for (Object obj : arg1) {
                isKey = obj.toString().startsWith("_");

                if (isKey) {
                    keyOut = obj.toString().replaceFirst("_","");
                    isRequiredKey = extractFields.contains(keyOut);
                    continue;
                }
                if (!isKey && isRequiredKey) {
                    outMap.put(keyOut, obj.toString());
                }
            }
            return outMap;
        }

        @Override
        public void initialize(Context context) {
            LOG.info("Initializing ExtractValue Function");
            Map<String, Object> config = getGlobalConfig(context);

            if (config.containsKey(EXTRACT_FIELDS_KEY)) {
                String fields = (String) config.get(EXTRACT_FIELDS_KEY);

                LOG.info("Found global config key ["+EXTRACT_FIELDS_KEY+"] with value : ["+fields+"]");
                Set<String> keySet = new HashSet<>(Arrays.asList(fields.split(Pattern.quote(","))));
                extractFields = keySet.stream().filter(line -> !line.startsWith("'"))
                                                //remove the technical '_' key indicators
                                                .collect(Collectors.toSet());
                //################//
                WhiteListRule.setConfigWhitelistFields(extractFields);
            }
            else {
                extractFields = new HashSet<>();
            }

            initialized = true;
        }

        private static Map<String, Object> getGlobalConfig(Context context) {
            return (Map<String, Object>) context.getCapability(Context.Capabilities.GLOBAL_CONFIG, false).orElse(new HashMap<>());
        }

        @Override
        public boolean isInitialized() {
            return initialized;
        }
    }

}