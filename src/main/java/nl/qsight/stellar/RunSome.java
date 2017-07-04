package nl.qsight.stellar;

import org.joda.time.DateTime;
import org.joda.time.format.DateTimeFormat;
import org.joda.time.format.DateTimeFormatter;

/**
 * Created by jknulst on 6/28/17.
 */
public class RunSome {

    private static DateTimeFormatter DTF = DateTimeFormat.forPattern("dd-MM-yyyy");

    public static void main(String[] args) {

        DateTime startDate = null;

        startDate = DTF.parseDateTime("23-06-1990");
        System.out.println(startDate.toString());
    }
}
