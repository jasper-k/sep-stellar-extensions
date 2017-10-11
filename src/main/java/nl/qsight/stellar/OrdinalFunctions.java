package nl.qsight.stellar;

import org.apache.metron.stellar.dsl.*;

import java.util.*;
import java.util.stream.Collectors;

public class OrdinalFunctions {

        private static org.apache.log4j.Logger LOG = org.apache.log4j.Logger.getLogger(nl.qsight.stellar.OrdinalFunctions.class);


        /**
         * Stellar Function: MAX
         * <p>
         * Return the maximum value of a list of input values
         */
        @Stellar(name = "MAX"
                , description = "Returns the maximum value of a list of input values"
                , params = {"list_of_values - List of values to evaluate. The list needs to contain only 1 type of Java Objects" +
                            " AND the Objects class must be comparable / ordinal"}
                , returns = "The highest value in the list, null if list is empty or values could not be ordered")
        public static class Max extends BaseStellarFunction {

            @Override
            public Object apply(List<Object> args) {

                if (args.size() < 1 || args.get(0) == null) {
                    throw new IllegalStateException("Requires at least a list object of values");
                }
                List list = (List<Object>) args.get(0);

                if (list.isEmpty()) {
                    return null;
                }

                List<Object> filteredList = (List<Object>) list.stream().filter(index -> !(index == null)).collect(Collectors.toList());

                if (filteredList.isEmpty()) {
                   return null;
                }

                try {

                    Collections.sort(filteredList,Collections.reverseOrder());
                } catch (ClassCastException e) {
                    throw new IllegalStateException("Mixed objects were submitted to MAX( List<Object>) function. List may only contain Strings only or Integers only");
                }

                return filteredList.get(0);
            }
        }


    /**
     * Stellar Function: MIN
     * <p>
     * Return the maximum value of a list of input values
     */
    @Stellar(name = "MIN"
            , description = "Returns the minimum value of a list of input values"
            , params = {"list_of_values - List of values to evaluate. The list needs to contain only 1 type of Java Objects" +
            " AND the Objects class must be comparable / ordinal"}
            , returns = "The highest value in the list, null if list is empty or values could not be ordered")
    public static class Min extends BaseStellarFunction {

        @Override
        public Object apply(List<Object> args) {

            if (args.size() < 1 || args.get(0) == null) {
                throw new IllegalStateException("Requires at least a list object of values");
            }
            List list = (List<Object>) args.get(0);

            if (list.isEmpty()) {
                return null;
            }

            List filteredList = (List<Object>) list.stream().filter(index -> !(index == null)).collect(Collectors.toList());

            if (filteredList.isEmpty()) {
                return null;
            }

            try {

                Collections.sort(filteredList);
            } catch (ClassCastException e) {
                throw new IllegalStateException("Mixed objects were submitted to MAX( List<Object>) function. List may only contain Strings only or Integers only");
            }

            return filteredList.get(0);
        }
    }
}
