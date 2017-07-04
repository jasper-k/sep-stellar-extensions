package nl.qsight.stellar;

import org.apache.metron.common.configuration.ConfigurationType;
import org.apache.metron.common.configuration.ConfigurationsUtils;
import org.apache.metron.common.configuration.EnrichmentConfigurations;

import org.apache.metron.common.dsl.BaseStellarFunction;
import org.apache.metron.common.dsl.Stellar;

import java.util.ArrayList;
import java.util.List;

/**
 {
    {
       "source_ip":{},
       "destination_ip.include":"192.168.0.0/24",
       "user":{},
       "time":{},
       "reason":"Can't fix the application",
       "new_risk":"4",
       "order":"3"
    },
    {
       "source_ip":{},
       "destination_ip.exclude":"192.168.0.10"
       "user":{},
       "time":{},
       "reason":"Allow risk, just for logging",
       "new_risk":"1",
       "order":"4"
    }
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
            , params = {"event - The event to check the whitelisting rules for"
            , "rule - The whitelisting rule expressed in JSON"}
            , returns = "True if the event/alert is whitelisted, false if otherwise.")
    public static class IsWhitelisted extends BaseStellarFunction {

        //to_do : source the fields to check from GLOBAL.config
        private static List<String> fieldsToCheck = new ArrayList<String>(){{
            add("source.ip");
            add("user");
            add("destination_ip");
            add("protocol");
        }};


        @Override
        public Object apply(List<Object> list) {

            if (list.size() < 2) {

            }

            return false;
        }
    }
}