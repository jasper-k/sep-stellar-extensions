package nl.qsight.stellar;

import nl.qsight.stellar.util.WhiteListRule;

import org.apache.metron.stellar.dsl.Context;
import org.apache.metron.stellar.dsl.Stellar;
import org.apache.metron.stellar.dsl.BaseStellarFunction;
import org.apache.metron.enrichment.stellar.SimpleHBaseEnrichmentFunctions;
import org.apache.metron.stellar.dsl.StellarFunction;
import org.json.simple.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
  {
 "rules": [{
     "ip_src_addr.include": "10.10.20.10/32",
    "ip_dst_addr.include": "192.168.0.0/24",
    "reason": "Cannot fix the application",
    "new_risk": "4",
    "order": "3"
    },{
    "ip_src_addr.include": "169.10.34.56/32",
    "ip_dst_addr.exclude": "192.168.0.10/32",
    "ip_dst_port.include": "8010,8012,9046",
    "user.include": "admin,supervisor",
    "protocol.include": "tcp",
    "time": "0 22 * * 1-5 | 2H",
    "reason": "Allow risk, just for logging",
    "new_risk": "1",
    "order": "4"
 }]
 }
 */
public class WhiteListingFunctions {

    protected static final Logger LOG = LoggerFactory.getLogger(WhiteListingFunctions.class);

    /**
     * Stellar Function: IS_WHITELISTED
     * <p>
     * Checks whether a raised alert is whitelisted according to a set of rules applied to various event fields
     */
    @Stellar(name = "IS_WHITELISTED"
            , description = "Checks whether a raised alert is whitelisted according to a set of rules applied to various event fields."
            , params = {"alert_kv's - A map of field names and their values of the alert to check against a rule"
            , "rule - The whitelisting rule expressed in a JSON String"}
            , returns = "JsonMap containing the whitelist reason, null if NOT whitelisted")
    public static class IsWhitelisted extends BaseStellarFunction {

        @Override
        public Object apply(List<Object> list) {

            if (list.size() < 2) {
                throw new IllegalStateException("Requires at least a Map of alert fields & values and a rule (JSON string)");
            }
            Map<String,Object> alertFieldsAndValues = (HashMap<String,Object>)list.get(0);
            String ruleAsJsonString = list.get(1).toString();

            WhiteListRule rule = new WhiteListRule(ruleAsJsonString);
            if (rule.isValid() && rule.isWhiteListed(alertFieldsAndValues)) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Alert : [" + new JSONObject(alertFieldsAndValues).toJSONString() + "] was whitelisted by rule : [" + ruleAsJsonString + "]");
                }
                return rule.getWhiteListAlertAdditions();
            }
            if (LOG.isDebugEnabled()) {
                LOG.debug("Alert : ["+new JSONObject(alertFieldsAndValues).toJSONString()+"] was NOT whitelisted by rule : ["+ruleAsJsonString+"]");
            }
            return null;
        }


    /**
     * Stellar Function: WHITELISTED
     * <p>
     * Checks whether a raised alert is whitelisted according to a set of rules applied to various event fields
     */
    @Stellar(name = "WHITELISTED"
            , description = "Checks whether a raised alert is whitelisted according to a set of rules applied to various event fields."
            , params = {"alert_kv's - A map of field names and their values of the alert to check against a rule"
            }
            , returns = "JsonMap containing the whitelist reason, null if NOT whitelisted")
    public static class whitelisted implements StellarFunction {

        @Override
        public Object apply(List<Object> list, Context context) {

            if (list.size() < 1) {
                throw new IllegalStateException("Requires at least a (Json) HBase result map and a Map of alert fields & values");
            }

            Map<String,Object> alertFieldsAndValues = (HashMap<String,Object>)list.get(0);

            if (alertFieldsAndValues == null) {
                throw new IllegalStateException("Parameter \"alert_kv's\" may not be NULL");
            }

            StellarFunction hBaseRulesLkpFunction = new SimpleHBaseEnrichmentFunctions.EnrichmentGet();
            if (!hBaseRulesLkpFunction.isInitialized()) {
                hBaseRulesLkpFunction.initialize(context);
            }

            Object hBaseLkpKey = alertFieldsAndValues.get("directive_lkp_key");

            if (hBaseLkpKey == null) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Alert : [" + new JSONObject(alertFieldsAndValues).toJSONString() + "] not whitelisted : REQUIRED key 'directive_lkp_key' is missing");
                }
                return null;
            }

            List<Object> args = new ArrayList<Object>() {{{ add(0,"whitelist_rule");
                                                            add(1, hBaseLkpKey);
                                                            add(2, "whitelist");
                                                            add(3, "rule");
                                                        }}};

            Object hBaseRulesReturn = hBaseRulesLkpFunction.apply(args, context);

            if (hBaseRulesReturn == null || ((HashMap<String,Object>)hBaseRulesReturn).get("rules") == null) {
                if (LOG.isDebugEnabled()) {
                    String lkpInfo = "lookup arguments : "+hBaseLkpKey.toString();
                    LOG.debug("Alert : [" + new JSONObject(alertFieldsAndValues).toJSONString() + "] not whitelisted : rules = NULL or EMPTY"+lkpInfo);
                }
                return null;
            }

            BaseStellarFunction jsonArrayToList = new JsonArrayToListFunction.JsonArrayToList();

            args.clear();
            args.add(((HashMap<String,Object>)hBaseRulesReturn).get("rules"));
            args.add("rules");

            Object rules = jsonArrayToList.apply(args);

            if (rules == null || ((List<String>)rules).isEmpty()) {
                if (LOG.isDebugEnabled()) {
                    String reason = "List<String> rules is NULL or empty";
                    LOG.debug("Alert : [" + new JSONObject(alertFieldsAndValues).toJSONString() + "] not whitelisted : rules = [" + reason + "]");
                }
                return null;
            }

            WhiteListRule wlRule;

            for (String ruleAsString : ((List<String>)rules)) {
                wlRule = new WhiteListRule(ruleAsString);

                if (wlRule.isValid() && wlRule.isWhiteListed(alertFieldsAndValues)) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Alert : [" + new JSONObject(alertFieldsAndValues).toJSONString() + "] was whitelisted by rule : [" + ruleAsString + "]");
                    }
                    //early exit, if 1 of the rules whitelists : stop
                    return wlRule.getWhiteListAlertAdditions();
                }
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Alert : ["+new JSONObject(alertFieldsAndValues).toJSONString()+"] was NOT whitelisted by rule : ["+ruleAsString+"]");
                }
            }

            return null;
        }

        @Override
        public void initialize(Context context) {

        }

        @Override
        public boolean isInitialized() {
            return false;
        }
    }
}
}