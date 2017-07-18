package nl.qsight.stellar;

import com.google.common.collect.ImmutableMap;
import org.adrianwalker.multilinestring.Multiline;

import org.apache.metron.common.dsl.Context;
import org.apache.metron.common.dsl.StellarFunctions;
import org.apache.metron.common.stellar.StellarProcessor;

import org.json.simple.JSONObject;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class WhiteListingTest {

  private List<String> mockList = new ArrayList<>();
  private static Context context;
  private static Object remapRes;
  private static final String EXTRACT_FIELDS_KEY = "sep.whitelist.extract.fields";

  /**
   {
   "ip_src_addr.include.single": "10.26.10.5",
   "ip_dst_addr.include.single": "172.20.3.18",
   "ip_src_port.include.single": "10564",
   "ip_dst_port.include.single": "21",
   "protocol.include.single": "tcp",
   "user.include.single": "john",
   "wl_reason": "Allow risk, just for logging",
   "wl_new_risk": "1",
   "wl_order": "1"
   }
   */
  @Multiline
  private String all__include__single;

  /**
   {
   "ip_src_addr.include.range": "10.26.10.0/29",
   "ip_dst_addr.include.range": "172.20.3.18/24",
   "wl_reason": "Allow risk, just for logging",
   "wl_new_risk": "1",
   "wl_order": "1"
   }
   */
  @Multiline
  private String ip__include__range;

  /**
   {
   "timestamp.include.range": "0 8 * * 1-5|8H",
   "wl_reason": "Allow risk, just for logging",
   "wl_new_risk": "1",
   "wl_order": "1"
   }
   */
  @Multiline
  private String time__include__range;

  /**
   {
   "user.include.multi": "john,marc",
   "wl_reason": "Allow risk, just for logging",
   "wl_new_risk": "1",
   "wl_order": "1"
   }
   */
  @Multiline
  private String user__include__multi;

  /**
   {
   "protocol.exclude.single": "udp",
   "wl_reason": "Allow risk, just for logging",
   "wl_new_risk": "1",
   "wl_order": "1"
   }
   */
  @Multiline
  private String protocol__exclude__single;

  /**
   {
   "ip_src_addr.exclude.range": "192.168.10.0/29",
   "wl_reason": "Allow risk, just for logging",
   "wl_new_risk": "1",
   "wl_order": "1"
   }
   */
  @Multiline
  private String ip__exclude__range;

  /**
   {
   "timestamp.exclude.range": "0 22 * * 1-5|2H",
   "wl_reason": "Allow risk, just for logging",
   "wl_new_risk": "1",
   "wl_order": "1"
   }
   */
  @Multiline
  private String time__exclude__range;

  private Map<String,String> alertMatch = new HashMap<String,String>() {{
    put("ip_src_addr","10.26.10.5");
    put("ip_dst_addr","172.20.3.18");
    put("ip_src_port","10564");
    put("ip_dst_port","21");
    put("protocol","tcp");
    put("user","John");
    put("timestamp","1498640504554"); //Wed Jun 28 2017 11:01:44 GMT+0200
  }};

  private Map<String,String> alertNoMatch = new HashMap<String,String>() {{
    put("ip_src_addr","10.26.10.5");
    put("ip_dst_addr","172.20.3.18");
    put("ip_src_port","10564");
    put("ip_dst_port","21");
    put("protocol","tcp");
    put("user","Marc");
    put("timestamp","1498640504554"); //Wed Jun 28 2017 11:01:44 GMT+0200
  }};

  @Before
  public void setup() throws Exception {
    context = new Context.Builder()
            .with( Context.Capabilities.GLOBAL_CONFIG
                    , () -> ImmutableMap.of(EXTRACT_FIELDS_KEY
                            , "'_ip_src_addr',ip_src_addr,'_ip_dst_addr',ip_dst_addr,'_ip_src_port',ip_src_port,'_ip_dst_port',ip_dst_port,'_protocol',protocol,'_user',user,'_timestamp',timestamp"
                    )
            )
            .build();

    remapRes = run("LIST_OF_FIELDS_AND_KEYS_TO_MAP(mockList)", ImmutableMap.of("mockList", mockList));
  }

  @Test
  public void testAllIncludeSingle() throws Exception {
    Object resultObj = run("IS_WHITELISTED(alert_kv,rule)", ImmutableMap.of("alert_kv", alertMatch, "rule", all__include__single));

    //Return object = null when NOT whitelisted, a JSONObject (Map) when whitelisted
    JSONObject whiteListReason = (JSONObject) resultObj;

    Assert.assertTrue(whiteListReason != null);
    Assert.assertTrue(whiteListReason.containsKey("wl_order"));
  }

  @Test
  public void testIpIncludeRange() throws Exception {
    Object resultObj = run("IS_WHITELISTED(alert_kv,rule)", ImmutableMap.of("alert_kv", alertMatch, "rule", ip__include__range));

    //Return object = null when NOT whitelisted, a JSONObject (Map) when whitelisted
    JSONObject whiteListReason = (JSONObject) resultObj;

    Assert.assertTrue(whiteListReason != null);
    Assert.assertTrue(whiteListReason.containsKey("wl_order"));
  }

  @Test
  public void testTimeIncludeRange() throws Exception {
    Object resultObj = run("IS_WHITELISTED(alert_kv,rule)", ImmutableMap.of("alert_kv", alertMatch, "rule", time__include__range));

    //Return object = null when NOT whitelisted, a JSONObject (Map) when whitelisted
    JSONObject whiteListReason = (JSONObject) resultObj;

    Assert.assertTrue(whiteListReason != null);
    Assert.assertTrue(whiteListReason.containsKey("wl_order"));
  }

  @Test
  public void testUserIncludeMulti() throws Exception {
    Object resultObj = run("IS_WHITELISTED(alert_kv,rule)", ImmutableMap.of("alert_kv", alertMatch, "rule", user__include__multi));

    //Return object = null when NOT whitelisted, a JSONObject (Map) when whitelisted
    JSONObject whiteListReason = (JSONObject) resultObj;

    Assert.assertTrue(whiteListReason != null);
    Assert.assertTrue(whiteListReason.containsKey("wl_order"));
  }

  @Test
  public void testExcludeSingle() throws Exception {
    Object resultObj = run("IS_WHITELISTED(alert_kv,rule)", ImmutableMap.of("alert_kv", alertMatch, "rule", protocol__exclude__single));

    //Return object = null when NOT whitelisted, a JSONObject (Map) when whitelisted
    JSONObject whiteListReason = (JSONObject) resultObj;

    Assert.assertTrue(whiteListReason != null);
    Assert.assertTrue(whiteListReason.containsKey("wl_order"));
  }

  @Test
  public void testIpExcludeRange() throws Exception {
    Object resultObj = run("IS_WHITELISTED(alert_kv,rule)", ImmutableMap.of("alert_kv", alertMatch, "rule", ip__exclude__range));

    //Return object = null when NOT whitelisted, a JSONObject (Map) when whitelisted
    JSONObject whiteListReason = (JSONObject) resultObj;

    Assert.assertTrue(whiteListReason != null);
    Assert.assertTrue(whiteListReason.containsKey("wl_order"));
  }

  @Test
  public void testTimeExcludeRange() throws Exception {
    Object resultObj = run("IS_WHITELISTED(alert_kv,rule)", ImmutableMap.of("alert_kv", alertMatch, "rule", time__exclude__range));

    //Return object = null when NOT whitelisted, a JSONObject (Map) when whitelisted
    JSONObject whiteListReason = (JSONObject) resultObj;

    Assert.assertTrue(whiteListReason != null);
    Assert.assertTrue(whiteListReason.containsKey("wl_order"));
  }

  @Test
  public void testNoMatch() throws Exception {
    Object resultObj = run("IS_WHITELISTED(alert_kv,rule)", ImmutableMap.of("alert_kv", alertNoMatch, "rule", all__include__single));

    //Return object = null when NOT whitelisted, a JSONObject (Map) when whitelisted
    JSONObject whiteListReason = (JSONObject) resultObj;

    Assert.assertNull(whiteListReason);
  }


  public Object run(String rule, Map<String, Object> variables) throws Exception {
    StellarProcessor processor = new StellarProcessor();
    return processor.parse(rule, x -> variables.get(x), StellarFunctions.FUNCTION_RESOLVER(), context);
  }

}