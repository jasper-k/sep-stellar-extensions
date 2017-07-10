package nl.qsight.stellar;

import nl.qsight.stellar.util.WhiteListRule;
import org.apache.metron.common.configuration.ConfigurationType;
import org.apache.metron.common.configuration.ConfigurationsUtils;
import org.apache.metron.common.configuration.EnrichmentConfigurations;

import org.apache.metron.common.dsl.BaseStellarFunction;
import org.apache.metron.common.dsl.Stellar;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
  {
 "rules": [{
     "ip_src_addr": "10.10.20.10",
    "ip_dst_addr.include.range": "192.168.0.0/24",
    "reason": "Cannot fix the application",
    "new_risk": "4",
    "order": "3"
    },{
    "ip_src_addr.include": "169.10.34.56",
    "ip_dst_addr.exclude": "192.168.0.10",
    "ip_dst_port.include.multi": "8010,8012,9046",
    "user.include.list": "admin,supervisor",
    "protocol": "tcp",
    "time": {},
    "reason": "Allow risk, just for logging",
    "new_risk": "1",
    "order": "4"
 }]
 }
 */

public class WhiteListingFunctions {

    /**
     * Stellar Function: IS_WHITELISTED
     * <p>
     * Checks whether a raised alert is whitelisted according to a set of rules applied to various event fields
     */
    @Stellar(name = "IS_WHITELISTED"
            , description = "Checks whether a raised alert is whitelisted according to a set of rules applied to various event fields."
            , params = {"alert_kv's - A map of field names and their values of the alert to check against a rule"
            , "rule - The whitelisting rule expressed in a JSON String"}
            , returns = "True if the event/alert is whitelisted, false if otherwise.")
    public static class IsWhitelisted extends BaseStellarFunction {



        @Override
        public Object apply(List<Object> list) {

            if (list.size() < 2) {
                throw new IllegalStateException("Requires at least a Map of alert fields & values and a rule (JSON string)");
            }
            Map<String,String> alertFieldsAndValues = (HashMap<String,String>)list.get(0);
            String ruleAsJsonString = list.get(1).toString();

            WhiteListRule rule = new WhiteListRule(ruleAsJsonString);
            if (rule.isValid() && rule.isWhiteListed(alertFieldsAndValues)) {
                    return rule.getWhiteListAlertAdditions();
            }

            return null;
        }
    }
}