package nl.qsight.stellar;

import org.apache.metron.stellar.dsl.BaseStellarFunction;
import org.apache.metron.stellar.dsl.Stellar;

import java.util.Collections;
import java.util.List;
import java.util.Map;


public class GetOrElseFunction {

    private static org.apache.log4j.Logger LOG = org.apache.log4j.Logger.getLogger(GetOrElseFunction.class);

/**
 * Stellar Function: GETORELSE
 * <p>
 * Return the maximum value of a list of input values
 */
@Stellar(name = "GETORELSE"
        , description = "Returns the value of a named variable OR an alternative variable or constant if "
        , params = {"variable - Variable to evaluate" +
        "default - Value to return if variable could not be found"}
        , returns = "Either the variable or the default if variable could not be found")
public static class GetOrElse extends BaseStellarFunction {

    @Override
    public Object apply(List<Object> args) {

        if (args.size() < 2) {
            throw new IllegalStateException("Requires at least a Stellar variable and a default if null");
        }

        Object evalObj = args.get(0);
        Object defaultObj = args.get(1);

        if (evalObj == null) {
            return defaultObj;
        }

        Object outObj = null;

        if (evalObj instanceof String && evalObj.toString().isEmpty()) {
            return defaultObj;
        }
        if (evalObj instanceof Map && ((Map)evalObj).isEmpty()) {
            return defaultObj;
        }
        if (evalObj instanceof List && ((List)evalObj).isEmpty()) {
            return defaultObj;
        }

        return (evalObj == null) ? defaultObj : evalObj;
    }
}

}
