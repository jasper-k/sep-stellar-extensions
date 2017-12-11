package nl.qsight.stellar;

import com.google.common.collect.ImmutableMap;
import org.adrianwalker.multilinestring.Multiline;

import org.apache.metron.stellar.common.StellarProcessor;
import org.apache.metron.stellar.dsl.*;

import org.json.simple.JSONObject;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

public class WhiteListingTest {

  private static Context context;
  private static final String EXTRACT_FIELDS_KEY = "sep.whitelist.extract.fields";

  /**
   {
   "ip_src_addr.include": "10.26.10.5/32",
   "ip_dst_addr.include": "172.20.3.18/32",
   "ip_src_port.include": "10564",
   "ip_dst_port.include": "21",
   "protocol.include": "tcp",
   "user.include": "john",
   "wl_reason": "Allow risk, just for logging",
   "wl_risk": "1",
   "wl_order": "1"
   }
   */
  @Multiline
  private String all_include;

  /**
   {
   "ip_src_addr.include": "10.26.10.0/29",
   "ip_dst_addr.include": "172.20.3.18/24",
   "wl_reason": "Allow risk, just for logging",
   "wl_risk": "1",
   "wl_order": "1"
   }
   */
  @Multiline
  private String ip_include;

  /**
   {
   "timestamp.include": "0 8 * * 1-5 | 8H",
   "wl_reason": "Allow risk, just for logging",
   "wl_risk": "1",
   "wl_order": "1"
   }
   */
  @Multiline
  private String time_include;

  /**
   {
   "user.include": "john,marc",
   "wl_reason": "Allow risk, just for logging",
   "wl_risk": "1",
   "wl_order": "1"
   }
   */
  @Multiline
  private String user_include;

  /**
   {
   "protocol.exclude": "udp",
   "wl_reason": "Allow risk, just for logging",
   "wl_risk": "1",
   "wl_order": "1"
   }
   */
  @Multiline
  private String protocol_exclude;

  /**
   {
   "ip_src_addr.exclude": "192.168.10.0/29",
   "wl_reason": "Allow risk, just for logging",
   "wl_risk": "1",
   "wl_order": "1"
   }
   */
  @Multiline
  private String ip_exclude;

  /**
   {
   "timestamp.exclude": "0 22 * * 1-5 | 2H",
   "wl_reason": "Allow risk, just for logging",
   "wl_risk": "1",
   "wl_order": "1"
   }
   */
  @Multiline
  private String time_exclude;

  /**
   {
   "detectors.include": "4535",
   "wl_reason": "Allow risk, just for logging",
   "wl_risk": "1",
   "wl_order": "1"
   }
   */
  @Multiline
  private String detector_include;

  private Map<String,Object> alertMatch = new HashMap<String,Object>() {{
    put("ip_src_addr","10.26.10.5");
    put("ip_dst_addr","172.20.3.18");
    put("ip_src_port","10564");
    put("ip_dst_port","21");
    put("protocol","tcp");
    put("user","John");
    put("detectors","4535");
    put("timestamp",1503318527755L); //Wed Jun 28 2017 11:01:44 GMT+0200
  }};

  private Map<String,Object> alertNoMatch = new HashMap<String,Object>() {{
    put("ip_src_addr","10.26.10.5");
    put("ip_dst_addr","172.20.3.18");
//    put("ip_src_port","9854");
    put("ip_src_port",null);
    put("ip_dst_port","21");
    put("protocol","tcp");
    put("user","John");
    put("timestamp",1503317538232L); //Wed Jun 28 2017 11:01:44 GMT+0200
  }};

  @Before
  public void setup() throws Exception {
    context = new Context.Builder()
            .with( Context.Capabilities.GLOBAL_CONFIG
                    , () -> ImmutableMap.of(EXTRACT_FIELDS_KEY
                            , "'_ip_src_addr',ip_src_addr,'_ip_dst_addr',ip_dst_addr,'_ip_src_port',ip_src_port,'_ip_dst_port',ip_dst_port,'_protocol',protocol,'_user',user,'_timestamp',timestamp,'_detectors',detectors"
                    )
            )
            .build();
  }

  @Test
  public void testAllIncludeSingle() throws Exception {
    Object resultObj = run("IS_WHITELISTED(alert_kv,rule)", ImmutableMap.of("alert_kv", alertMatch, "rule", all_include));

    //Return object = null when NOT whitelisted, a JSONObject (Map) when whitelisted
    JSONObject whiteListReason = (JSONObject) resultObj;

    Assert.assertTrue(whiteListReason != null);
    Assert.assertTrue(whiteListReason.containsKey("reason"));
  }

  @Test
  public void testIpIncludeRange() throws Exception {
    Object resultObj = run("IS_WHITELISTED(alert_kv,rule)", ImmutableMap.of("alert_kv", alertMatch, "rule", ip_include));

    //Return object = null when NOT whitelisted, a JSONObject (Map) when whitelisted
    JSONObject whiteListReason = (JSONObject) resultObj;

    Assert.assertTrue(whiteListReason != null);
    Assert.assertTrue(whiteListReason.containsKey("reason"));
  }

  @Test
  public void testTimeIncludeRange() throws Exception {
    Object resultObj = run("IS_WHITELISTED(alert_kv,rule)", ImmutableMap.of("alert_kv", alertMatch, "rule", time_include));

    //Return object = null when NOT whitelisted, a JSONObject (Map) when whitelisted
    JSONObject whiteListReason = (JSONObject) resultObj;

    Assert.assertTrue(whiteListReason != null);
    Assert.assertTrue(whiteListReason.containsKey("reason"));
  }

  @Test
  public void testUserIncludeMulti() throws Exception {
    Object resultObj = run("IS_WHITELISTED(alert_kv,rule)", ImmutableMap.of("alert_kv", alertMatch, "rule", user_include));

    //Return object = null when NOT whitelisted, a JSONObject (Map) when whitelisted
    JSONObject whiteListReason = (JSONObject) resultObj;

    Assert.assertTrue(whiteListReason != null);
    Assert.assertTrue(whiteListReason.containsKey("reason"));
  }

  @Test
  public void testExcludeSingle() throws Exception {
    Object resultObj = run("IS_WHITELISTED(alert_kv,rule)", ImmutableMap.of("alert_kv", alertMatch, "rule", protocol_exclude));

    //Return object = null when NOT whitelisted, a JSONObject (Map) when whitelisted
    JSONObject whiteListReason = (JSONObject) resultObj;

    Assert.assertTrue(whiteListReason != null);
    Assert.assertTrue(whiteListReason.containsKey("reason"));
  }

  @Test
  public void testIpExcludeRange() throws Exception {
    Object resultObj = run("IS_WHITELISTED(alert_kv,rule)", ImmutableMap.of("alert_kv", alertMatch, "rule", ip_exclude));

    //Return object = null when NOT whitelisted, a JSONObject (Map) when whitelisted
    JSONObject whiteListReason = (JSONObject) resultObj;

    Assert.assertTrue(whiteListReason != null);
    Assert.assertTrue(whiteListReason.containsKey("reason"));
  }

  @Test
  public void testTimeExcludeRange() throws Exception {
    Object resultObj = run("IS_WHITELISTED(alert_kv,rule)", ImmutableMap.of("alert_kv", alertMatch, "rule", time_exclude));

    //Return object = null when NOT whitelisted, a JSONObject (Map) when whitelisted
    JSONObject whiteListReason = (JSONObject) resultObj;

    Assert.assertNull(whiteListReason);
  }

  @Test
  public void testNoMatch() throws Exception {
    Object resultObj = run("IS_WHITELISTED(alert_kv,rule)", ImmutableMap.of("alert_kv", alertNoMatch, "rule", all_include));

    //Return object = null when NOT whitelisted, a JSONObject (Map) when whitelisted
    JSONObject whiteListReason = (JSONObject) resultObj;

    Assert.assertNull(whiteListReason);
  }

  public Object run(String rule, Map<String, Object> variables) throws Exception {
    StellarProcessor processor = new StellarProcessor();
    return processor.parse(rule, new DefaultVariableResolver(x -> variables.get(x),x -> variables.containsKey(x)), StellarFunctions.FUNCTION_RESOLVER(), context);
  }

  @Test
  public void testDetectorIncludeSingle() throws Exception {
    Object resultObj = run("IS_WHITELISTED(alert_kv,rule)", ImmutableMap.of("alert_kv", alertMatch, "rule", detector_include));

    //Return object = null when NOT whitelisted, a JSONObject (Map) when whitelisted
    JSONObject whiteListReason = (JSONObject) resultObj;

    Assert.assertTrue(whiteListReason != null);
    Assert.assertTrue(whiteListReason.containsKey("reason"));
  }

}