package nl.qsight.stellar.util;

import com.cronutils.model.Cron;
import com.cronutils.model.CronType;
import com.cronutils.model.definition.CronDefinition;
import com.cronutils.model.definition.CronDefinitionBuilder;
import com.cronutils.model.time.ExecutionTime;
import com.cronutils.parser.CronParser;
import org.apache.log4j.Logger;
import org.threeten.bp.LocalDateTime;
import org.threeten.bp.ZoneOffset;
import org.threeten.bp.ZonedDateTime;
import org.threeten.bp.format.DateTimeFormatter;


/**
   "time.include.range": "0 23 * 6 2-6 | 8H"
 */
public class TimeRange {

    private static final Logger LOG = Logger.getLogger(TimeRange.class);

    private String definition;
    private Cron unixCron;
    private ExecutionTime executionTime;
    private Long durationInSeconds;

    private Boolean isValid = false;

    public TimeRange(String def) {
        definition = def;
        parseDefinition();
    }

    private void parseDefinition() {

        try {
            String[] defParts = definition.split("\\|");

            if (defParts.length < 2 ) {
                throw new Exception("Could not parse whitelist time range def : "+definition);
            }
            durationInSeconds = getWhiteListDuration(defParts[1].trim());
            parseCron(defParts[0].trim());
        }
        catch (Exception e) {
            LOG.error(e.getMessage());
        }

        if (executionTime != null) {
            isValid = true;
        }
    }

    private void parseCron(String cronDef) {

        CronDefinition cronDefinition = CronDefinitionBuilder.instanceDefinitionFor(CronType.UNIX);
        CronParser parser = new CronParser(cronDefinition);

        unixCron = parser.parse(cronDef);
        unixCron.validate();
        executionTime = ExecutionTime.forCron(unixCron);
    }

    public Boolean isAlertInWhiteListRange(Long timestamp) {

        LocalDateTime alertLocalDateTime = LocalDateTime.ofEpochSecond(timestamp/1000L, 0, ZoneOffset.UTC);
        ZonedDateTime alertZonedDateTime = ZonedDateTime.of(alertLocalDateTime, ZoneOffset.UTC);
        ZonedDateTime startLastWhiteListingBeforeAlert = executionTime.lastExecution(alertZonedDateTime).get();
        LocalDateTime endTimeWhitelisting = startLastWhiteListingBeforeAlert.toLocalDateTime().plusSeconds(durationInSeconds);

        Boolean inTimeRange = alertLocalDateTime.isBefore(endTimeWhitelisting);

        if (LOG.isDebugEnabled()) {
            String verdict = inTimeRange ? "is within" : "not in";
            LOG.debug("Timerange Eval Detail : [" + timestamp + " / "+ alertLocalDateTime.format(DateTimeFormatter.ISO_DATE_TIME)+"] "+verdict+ " timerange definition [" + definition+ "] ");
        }

        if (inTimeRange){
            return true;
        }
        return false;
    }

    private static Long getWhiteListDuration(String durationDef) throws Exception {

        try {
              String[] durationStringParts = durationDef.split("(?<=\\d)(?=\\D)");

              Long duration = Long.parseLong(durationStringParts[0]);
              String duration_unit = durationStringParts[1];

              switch (duration_unit) {
                    case "M":
                        return duration*60L;
                    case "H":
                        return duration*3600L;
                    case "D":
                        return duration*86400L;
                    default:
                        throw new Exception();
                }

        } catch (Exception e) {
            throw new Exception("Could not parse or get whitelist duration from whitelist time range notation : "+durationDef,e.getCause());
        }

    }

    public Boolean isValid() {
        return isValid;
    }

    public String getDefinition() {
        return definition;
    }

}
