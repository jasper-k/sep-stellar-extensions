package nl.qsight.stellar;

import org.apache.log4j.Logger;
import org.apache.metron.common.dsl.BaseStellarFunction;
import org.apache.metron.common.dsl.Stellar;

import org.apache.metron.common.dsl.ParseException;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import java.util.*;

/**
 {
 "rules": [{
    "ip_src_addr": "10.10.20.10",
    "ip_dst_addr.include.range": "192.168.0.0/24",
    "reason": "Cannot fix the application",
    "new_risk": "4",
    "order": "3"
    },
    {"ip_src_addr.include": "169.10.34.56",
    "ip_dst_addr.exclude": "192.168.0.10",
    "ip_dst_port.include.list": "(8010,8012,9046)",
    "user.include.list": "(admin,supervisor)",
    "protocol": "tcp",
    "time": {},
    "reason": "Allow risk, just for logging",
    "new_risk": "1",
    "order": "4"
 }]
 }
 */

public class JsonArrayToListFunction {

    private static Logger LOG = Logger.getLogger(JsonArrayToListFunction.class);
    /**
     * Stellar Function: JSONARRAY_TOLIST
     * <p>
     * Converts a JSON object passed as string into a list of (JSON) strings. The key of the JSON array has to be passed as a parameter
     */
    @Stellar(name = "JSONARRAY_TOLIST"
            , description = "Converts a JSON object passed as string into a list of (JSON) strings."
            , params = {"json_as_string - The JSON Object to extract from as a string"
            , "array_key - The key of the JSON array to turn into a list"}
            , returns = "List of all the JSON array members as strings")
    public static class JsonArrayToList extends BaseStellarFunction {

        @Override
        public Object apply(List<Object> list) throws ParseException{

            if (list.size() < 2) {
                throw new IllegalStateException("Requires at least a JSON string and a key (string)");
            }
            String jsonAsString = (String) list.get(0);
            String key = (String) list.get(1);
            JSONObject json;

            JSONParser jsonParser = new JSONParser();
            try {
                json = (JSONObject) jsonParser.parse(jsonAsString);
            } catch (org.json.simple.parser.ParseException e) {
                throw new ParseException("Argument ["+jsonAsString+"] could not be parsed as valid JSON",e);
             }

            List<String> outList = new ArrayList<>();
            Object rulesObject = json.get(key);
            if (rulesObject != null) {
                for (Object rule : ((JSONArray) rulesObject)) {
                    outList.add(rule.toString());
                }
            }
                return outList;
        }
    }
}
