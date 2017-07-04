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

public class ExtractValuesFunction {

    private static Logger LOG = Logger.getLogger(ExtractValuesFunction.class);
    /**
     * Stellar Function: EXTRACT_VALUES
     * <p>
     * Extracts a configurable set of values from the telemetry event into a single HashMap.
     */
    @Stellar(name = "EXTRACT_VALUES"
            , description = "Extracts a configurable set of values from the telemetry event into a single HashMap."
            , params = {"json_as_string - The JSON Object to extract from as a string"
            , "array_key - The key of the JSON array to turn into a list"}
            , returns = "List of all the JSON array members as strings")
    public static class ExtractValues extends BaseStellarFunction {


        @Override
        public Object apply(List<Object> list) throws ParseException {


            return null;
        }
    }
}