package nl.qsight.stellar.util;


import org.apache.commons.lang3.StringUtils;
import org.apache.commons.net.util.SubnetUtils;
import org.apache.log4j.Logger;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import java.util.*;

/**
        {
        "ip_src_addr.include.single": "169.10.34.56",
        "ip_dst_addr.exclude.single": "192.168.0.10",
        "ip_dst_port.include.multi": "8010,8012,9046",
        "user.include.multi": "admin,supervisor",
        "protocol.include.single": "tcp",
        "time.include.range": "0 23 * 6 2-6|8H",
        "wl_reason": "Allow risk, just for logging",
        "wl_new_risk": "1",
        "wl_order": "4"
        }
*/
public class WhiteListRule {

    private static final Logger LOG = Logger.getLogger(WhiteListRule.class);
    private static Set<String> configWhitelistFields;

    private String ruleAsJSONString;
    private JSONObject ruleAsJSON;
    private HashMap<String,String> relevantRuleComponents = new HashMap();

    private Boolean isWhiteListed;
    private Boolean isValid = false;
    private String timeRangeKey;
    private TimeRange timeRange;
    private Boolean hasTimeRange = false;

    public enum Filter {
        INCLUDE,
        EXCLUDE;

        private String predicate;

    }

    public enum Evaluation {
        RANGE_TIME,
        RANGE_IP,
        MULTI,
        SINGLE,
        WILDCARD;

        private void set(){

        }
    }

    public WhiteListRule(String jsonAsString) {

        ruleAsJSONString = jsonAsString;
        parseJson(ruleAsJSONString);
        validateRule();
    }

    private void validateRule() {
        if (configWhitelistFields == null || configWhitelistFields.isEmpty()) {
            LOG.error("Whitelist Rule ["+ruleAsJSONString+"] could not be parsed. Reason [GlobalConfig property 'sep.whitelist.extract.fields' not available]");
            return;
        }
        setRelevantRules();
        if (relevantRuleComponents.isEmpty()) {
            LOG.error("Whitelist Rule ["+ruleAsJSONString+"] could not be enforced. Reason [Rule has no fields that are part of 'sep.whitelist.extract.fields' in Global Config]");
            return;
        }
        if (timeRange != null) {
            if (timeRange.isValid()) {
                hasTimeRange = true;
            } else {
                LOG.error(String.format("Whitelist Rule %s has invalid time range definition %s", ruleAsJSONString, timeRange.getDefinition()));
                return;
            }
        }

        isValid=true;

    }

    private void setRelevantRules() {

        Iterator<Map.Entry> it = ruleAsJSON.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry entry = it.next();
            String[] ruleFieldKeyParts = ((String) entry.getKey()).split("\\.");
            String ruleFieldKey = ruleFieldKeyParts[0];
            if (configWhitelistFields.contains(ruleFieldKey)) {
                relevantRuleComponents.put(entry.getKey().toString(), entry.getValue().toString());
            }
            if (ruleFieldKey.equals("time")) {
                timeRangeKey = entry.getKey().toString();
                timeRange = new TimeRange(entry.getValue().toString());
            }
        }
    }

    public Boolean isWhiteListed(Map<String,String> alertFieldsAndValues) {
        Iterator<Map.Entry<String,String>> it = relevantRuleComponents.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry<String, String> ruleComponent = it.next();
            String[] rulePartKeyComponents = ruleComponent.getKey().split("\\.");
            String ruleField = rulePartKeyComponents[0];
            String ruleFilter = rulePartKeyComponents[1];
            String ruleEvaluation = rulePartKeyComponents[2];

            //ruleComponent cannot be checked: field is missing in alert
            if (!alertFieldsAndValues.containsKey(ruleField)) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("WhiteListEval Detail : [" + new JSONObject(alertFieldsAndValues).toJSONString() + "] not whitelisted [exit 1] : ruleField [" + ruleField + "] not found in field values");
                }
                return false;
            }

            String alertValue = alertFieldsAndValues.get(ruleField);

            if (ruleEvaluation.equals("single")) {
                isWhiteListed = StringUtils.equalsIgnoreCase(ruleComponent.getValue(), alertValue);
            } else if (ruleEvaluation.equals("multi")) {
                String[] componentValues = ruleComponent.getValue().split(",");
                List<String> list = Arrays.asList(componentValues);
                isWhiteListed = list.stream().anyMatch(alertValue::equalsIgnoreCase);
            } else if (ruleEvaluation.equals("range")) {
                // check time
                if (ruleField.equals("time")) {
                    isWhiteListed = timeRange.isAlertInWhiteListRange(Long.parseLong(alertFieldsAndValues.get("timestamp")));
                }

                // check ip range
                if (ruleField.equals("ip_src_addr") || ruleField.equals("ip_dst_addr")) {
                    String[] componentValues = ruleComponent.getValue().split(",");
                    for (String s : componentValues) {
                        SubnetUtils utils = new SubnetUtils(s);
                        utils.setInclusiveHostCount(true);
                        isWhiteListed = utils.getInfo().isInRange(alertValue);
                    }
                }
            }

            // on exclude flip isWhiteListed
            if (ruleFilter.equals("exclude")) {
                return !isWhiteListed;
            }
        }

        return isWhiteListed;

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
            if (key.toString().startsWith("wl_")) {
                resJson.put(key,ruleAsJSON.get(key));
            }
        }
        return resJson;
    }

    public static Set<String> getConfigWhitelistFields() {
        return configWhitelistFields;
    }

    public static void setConfigWhitelistFields(Set<String> configWhitelistFields) {
        WhiteListRule.configWhitelistFields = configWhitelistFields;
    }

}
