package nl.qsight.stellar.util;

import org.apache.commons.net.util.SubnetUtils;
import org.apache.log4j.Logger;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import java.util.*;

public class WhiteListRule {

    private static final Logger LOG = Logger.getLogger(WhiteListRule.class);

    private String ruleAsJSONString;
    private JSONObject ruleAsJSON;

    private Boolean isValid = false;
    private TimeRange timeRange;
    private HashMap<String,String> relevantRuleComponents = new HashMap();

    public WhiteListRule(String jsonAsString) {

        ruleAsJSONString = jsonAsString;
        parseJson(ruleAsJSONString);
        setAndValidateRule();
    }

    private void setAndValidateRule() {

        Iterator<Map.Entry> it = ruleAsJSON.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry entry = it.next();
            String ruleFieldKey = entry.getKey().toString();
            if (!ruleFieldKey.startsWith("wl_")) {
                relevantRuleComponents.put(ruleFieldKey, entry.getValue().toString());
            }
            if (ruleFieldKey.startsWith("timestamp")) {
                timeRange = new TimeRange(entry.getValue().toString());
            }
        }
        if (timeRange != null && !timeRange.isValid()) {
                LOG.error(String.format("Whitelist Rule %s has invalid time range definition %s", ruleAsJSONString, timeRange.getDefinition()));
                return;
        }

        isValid=true;
    }


    public Boolean isWhiteListed(Map<String,Object> alertFieldsAndValues) {

        //This boolean holds the verdict of a whitelist condition, on checking 1 complete rule. The verdict starts at false, but can change
        //during the loop through all rule components.
        Boolean isWhiteListedSoFar = false;

        Iterator<Map.Entry<String,String>> it = ruleAsJSON.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry<String, String> ruleComponent = it.next();

            //A complete WL rule also contains fields that are meant to be appended to the stream
            //but are not rule components that can be checked
            if (ruleComponent.getKey().toString().startsWith("wl_")) {
                continue;
            }

            String[] rulePartKeyComponents = ruleComponent.getKey().split("\\.");
            String ruleField = rulePartKeyComponents[0];
            String ruleFilter = rulePartKeyComponents[1];

            // ruleComponent (key) cannot be checked: field is missing in alert
            // OR
            // ruleValue itself is NULL
            if (!alertFieldsAndValues.containsKey(ruleField) || alertFieldsAndValues.get(ruleField) == null) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("WhiteListEval Detail : [" + new JSONObject(alertFieldsAndValues).toJSONString() + "] not whitelisted [exit 1] : ruleField [" + ruleField + "] not found in field values");
                }
                return false;
            }

            String ruleValue = ruleComponent.getValue();
            Object alertValue = alertFieldsAndValues.get(ruleField);

            //Rule DSL notation allows for single value or multiple comma separated values, we don't care
            String[] ruleComponentValues = ruleValue.split(",");

            if (ruleField.equals("timestamp")) {

                //early exit, cause whatever the rule might grant based on alert field values, the specified timerange does not fit
                if (!timeRange.isAlertInWhiteListRange(Long.parseLong(alertValue.toString()))) {
                    return false;
                }
                isWhiteListedSoFar = true;

            } else if (ruleField.equals("ip_src_addr") || ruleField.equals("ip_dst_addr")) {
                //Specific check for alert values of ip type
                for (String s : ruleComponentValues) {
                    SubnetUtils utils;
                    try {
                        utils = new SubnetUtils(s);
                    } catch (IllegalArgumentException e) {
                        LOG.warn(String.format("Invalid cidr address: [%s]. %s", s, e));
                        break;
                    }

                    utils.setInclusiveHostCount(true);

                    // if one value matched, early exit
                    if (utils.getInfo().isInRange((String)alertValue)) {
                        isWhiteListedSoFar = true;
                        break;
                    }
                }
            } else {
                boolean matchingValue = false;
                for (int i = 0; i < ruleComponentValues.length && !matchingValue; i++) {
                    matchingValue = alertValue.toString().equalsIgnoreCase(ruleComponentValues[i]);
                }
                isWhiteListedSoFar = matchingValue;

            }

            // on exclude flip isWhiteListed
            isWhiteListedSoFar = ruleFilter.equals("exclude") ? !isWhiteListedSoFar : isWhiteListedSoFar;

            // early exit, if after checking 1 complete rule component the verdict isWhiteListedSoFar is still false, we can exit the rule as
            //it can never apply
            if (!isWhiteListedSoFar) {
                return false;
            }
        }

        return isWhiteListedSoFar;
    }

    private void parseJson(String jsonAsString) {

        JSONParser parser = new JSONParser();
        try {
            ruleAsJSON = (JSONObject) parser.parse(jsonAsString);
        } catch (ParseException e) {
            e.printStackTrace();
        }

    }

    public Boolean isValid() {
        return isValid;
    }

    public JSONObject getWhiteListAlertAdditions() {

        JSONObject resJson = new JSONObject();
        for (Object key : ruleAsJSON.keySet()) {
            if (key.toString().startsWith("wl_") && !key.toString().equalsIgnoreCase("wl_order")) {
                resJson.put(key.toString().replace("wl_", ""), ruleAsJSON.get(key));
            }
        }
        return resJson;
    }
}
