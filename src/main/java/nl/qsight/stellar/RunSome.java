package nl.qsight.stellar;

import org.joda.time.DateTime;
import org.joda.time.format.DateTimeFormat;
import org.joda.time.format.DateTimeFormatter;

import java.util.ArrayList;
import java.util.List;

/**
 * Created by jknulst on 6/28/17.
 */
public class RunSome {

    private static DateTimeFormatter DTF = DateTimeFormat.forPattern("dd-MM-yyyy");

    public static void main(String[] args) {

        DateTime startDate = null;

        startDate = DTF.parseDateTime("23-06-1990");
        System.out.println(startDate.toString());
        List<String> bla = new ArrayList<>();

        bla.add("niets");
        bla.add(null);
        bla.add("iets");
        bla.add(null);
        bla.size();
        System.out.println("0"+bla.get(0));
        System.out.println("1"+bla.get(1));
        System.out.println("2"+bla.get(2));
        System.out.println("3"+bla.get(3));



    }
}