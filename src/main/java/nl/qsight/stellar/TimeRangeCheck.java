package nl.qsight.stellar;

/**
 * Created by jknulst on 6/27/17.
 */
import com.cronutils.model.Cron;
import com.cronutils.model.CronType;
import com.cronutils.model.definition.CronDefinition;
import com.cronutils.model.definition.CronDefinitionBuilder;
import com.cronutils.model.time.ExecutionTime;
import com.cronutils.parser.CronParser;
import org.apache.log4j.Logger;
import org.apache.metron.common.dsl.BaseStellarFunction;
import org.apache.metron.common.dsl.ParseException;
import org.apache.metron.common.dsl.Stellar;
import org.apache.metron.common.utils.ConversionUtils;
import org.joda.time.DateTime;
import org.joda.time.format.DateTimeFormat;
import org.joda.time.format.DateTimeFormatter;

import org.threeten.bp.Duration;
import org.threeten.bp.ZoneOffset;
import org.threeten.bp.ZonedDateTime;
import org.threeten.bp.LocalDateTime;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import java.util.*;

/**
 *
 *  {"time_range":
 {"start":
 {"minutes":"0,10,20"
 ,"hours":"/5"
 ,"days":"12-28"
 ,"weekdays": "3,4"
 ,"month": "1-6"
 },
 "cron" : "0 23 * ? * MON-FRI *",
 "duration":
 {"hours":"8"
 },
 "start_date":"23-06-2017"
 "end_date":"28-12-2018"
 }
 }
 */

public class TimeRangeCheck {

  private static final Logger LOG = Logger.getLogger(TimeRangeCheck.class);

  private static String START_DATE = "start_date";
  private static String END_DATE = "end_date";
  private static String CRON_DEF = "cron";
  private static DateTimeFormatter DTF = DateTimeFormat.forPattern("dd-MM-yyyy");
  private static String DURATION = "duration";
  private static String DURATION_UNIT = "duration_unit";
  /**
   * Stellar Function: IN_TIME_RANGE
   *
   * Checks whether an epoch is within bounds of a time window expressed in standard Unix Cron notation.
   *
   *
   */
  @Stellar( name="IN_TIME_RANGE"
          , description="Checks whether an epoch is within bounds of a time window expressed in standard Unix Cron notation."
          , params = { "dateTime - The datetime on the event as a long representing the milliseconds since unix epoch"
          , "schedule - The schedule expressed  in JSON based by the Cron recursive syntax notation"}
          , returns = "True if the event ts is within bounds of the schedule, false if otherwise.")
  public static class InTimeRange extends BaseStellarFunction {
    @Override
    public Object apply(List<Object> args) {

      // expects epoch millis, otherwise defaults to current time
      Long eventEpoch = getOrDefault(args, 0, Long.class, System.currentTimeMillis());
      if(eventEpoch == null) {
        return null;  // invalid argument
      }

      DateTime startDate = null;
      DateTime endDate = null;
      DateTime eventDate = new DateTime(eventEpoch);
      JSONParser jsonParser = new JSONParser();

      JSONObject rangeDefJSON = null;
      try {
        rangeDefJSON = (JSONObject) jsonParser.parse((String) args.get(1));
      } catch (org.json.simple.parser.ParseException e) {
        e.printStackTrace();
      }

      if (rangeDefJSON.containsKey(START_DATE)) {
        startDate = DTF.parseDateTime((String)rangeDefJSON.get(START_DATE));
      }
      if (rangeDefJSON.containsKey(END_DATE)) {
        endDate = DTF.parseDateTime((String)rangeDefJSON.get(END_DATE));
      }
      //Check whether time based whitelist is/was activated at the moment of the event
      //based on start and end dates of time range. If the whitelist was not active at the event date,
      //no whitelisting can be granted by it
      if (startDate != null && eventDate.isBefore(startDate)) {return true;}
      if (endDate != null && endDate.isAfter(eventDate)) {return true;}


      if (rangeDefJSON.containsKey(CRON_DEF)) {
        String cronDef = (String) rangeDefJSON.get(CRON_DEF);

        CronDefinition cronDefinition = CronDefinitionBuilder.instanceDefinitionFor(CronType.UNIX);
        CronParser parser = new CronParser(cronDefinition);
        Cron unixCron = parser.parse(cronDef);

        LocalDateTime eventLocalDateTime = org.threeten.bp.LocalDateTime.ofEpochSecond(eventEpoch/1000L, 0, ZoneOffset.UTC);
        ZonedDateTime eventZonedDateTime = ZonedDateTime.of(eventLocalDateTime,ZoneOffset.UTC);

        ExecutionTime executionTime = ExecutionTime.forCron(unixCron);
        ZonedDateTime lastExecution = executionTime.lastExecution(eventZonedDateTime).get();

        Long durationInSeconds = -1L;
        try {
          durationInSeconds = whiteListDuration(rangeDefJSON);
        } catch (WhitelistTimeRangeParsingException e) {
          e.printStackTrace();
          LOG.error("Whitelist time range could not be determined for event. Event will NOT be whitelisted by default!");
          return false;
        }

        LocalDateTime endTimeWhitelisting = lastExecution.toLocalDateTime().plusSeconds(durationInSeconds);
        if (eventLocalDateTime.isAfter(lastExecution.toLocalDateTime()) && eventLocalDateTime.isBefore(endTimeWhitelisting)){
          return true;

        }


      }
      else {
        LOG.error("No valid whilelisting time range found");
        return false;
      }



      return true;
    }
  }


  private static Long whiteListDuration(JSONObject rangeDefJSON) throws WhitelistTimeRangeParsingException {

    try {
      if (rangeDefJSON.containsKey(DURATION) && rangeDefJSON.containsKey(DURATION_UNIT)) {
        Long duration = Long.parseLong((String) rangeDefJSON.get(DURATION));
        String duration_unit = (String) rangeDefJSON.get(DURATION_UNIT);

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
      } else {
        throw new Exception();
      }

    } catch (Exception e) {
      throw new WhitelistTimeRangeParsingException("Could not parse or get whitelist duration from whitelist time range notation : "+rangeDefJSON.toJSONString(),e.getCause());

    }
  }



  /**
   * Gets the value from a list of arguments.
   *
   * If the argument at the specified position does not exist, a default value will be returned.
   * If the argument at the specified position exists, but cannot be coerced to the right type, null is returned.
   * Otherwise, the argument value is returned.
   *
   * @param args A list of arguments.
   * @param position The position of the argument to get.
   * @param clazz The type of class expected.
   * @param defaultValue The default value.
   * @param <T> The expected type of the argument.
   */
  private static <T> T getOrDefault(List<Object> args, int position, Class<T> clazz, T defaultValue) {
    T result = defaultValue;
    if(args.size() > position) {
      result = ConversionUtils.convert(args.get(position), clazz);
    }
    return result;
  }
}
