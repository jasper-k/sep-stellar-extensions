package nl.qsight.stellar;

import org.apache.log4j.Logger;
import org.apache.metron.common.dsl.BaseStellarFunction;
import org.apache.metron.common.dsl.Stellar;

import org.apache.metron.common.dsl.ParseException;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.IllegalFormatException;
import java.util.List;

/**
 {
 "rules": [{
    "source_ip": "10.10.20.10",
    "destination_ip.include": "192.168.0.0/24",
    "reason": "Can't fix the application",
    "new_risk": "4",
    "order": "3"  
 },    {      
    "source_ip": {},
    "destination_ip.exclude": "192.168.0.10",
    "user": {!admin},
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
     * Converts a JSON object passed as string into a list of strings. The key of the JSON array has to be passed as a parameter
     */
    @Stellar(name = "JSONARRAY_TOLIST"
            , description = "Checks whether a raised alert is whitelisted according to a set of rules applied to various event fields."
            , params = {"json_as_string - The JSON Object to extract from as a string"
            , "array_key - The key of the JSON array to turn into a list"}
            , returns = "List of all the JSON array members as strings")
    public static class JsonArrayToList extends BaseStellarFunction {

        @Override
        public Object apply(List<Object> list) throws ParseException{

            if (!(list.size() == 2)) {
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

            Object rulesObject = json.get(key);
            if (rulesObject != null) {

                return ((JSONArray) rulesObject);
            }
            else {
                return new JSONArray();
            }

        }


    }
}
