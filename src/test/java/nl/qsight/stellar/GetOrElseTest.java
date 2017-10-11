package nl.qsight.stellar;

import com.google.common.collect.ImmutableMap;
import org.adrianwalker.multilinestring.Multiline;
import org.apache.commons.collections.map.HashedMap;
import org.apache.metron.stellar.common.StellarProcessor;
import org.apache.metron.stellar.common.utils.StellarProcessorUtils;
import org.apache.metron.stellar.dsl.Context;
import org.apache.metron.stellar.dsl.DefaultVariableResolver;
import org.apache.metron.stellar.dsl.StellarFunctions;
import org.json.simple.JSONObject;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

public class GetOrElseTest {

  private static Context context;
  private static final String EXTRACT_FIELDS_KEY = "sep.whitelist.extract.fields";


  private Map<String,Object> alertMatch = new HashMap<String,Object>() {{
    put("ip_src_addr","10.26.10.5");
    put("ip_dst_addr","172.20.3.18");
    put("ip_src_port","10564");
    put("ip_dst_port","21");
    put("protocol","tcp");
    put("user","John");
    put("timestamp",1503318527755L); //Wed Jun 28 2017 11:01:44 GMT+0200
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
  }

  @Test
  public void testVarNotNull() throws Exception {
    Object resultObj = run("GETORELSE(alert_kv,'alternative')", ImmutableMap.of("alert_kv", alertMatch));

    HashMap<String,String> result = (HashMap<String,String>) resultObj;
    Assert.assertTrue(result!= null);
    Assert.assertTrue(result.containsKey("protocol"));
  }

  @Test
  public void testStringNotNull() throws Exception {
    Object resultObj = run("GETORELSE('bla','alternative')", ImmutableMap.of("alert_kv", alertMatch));

    Assert.assertTrue(resultObj != null);
    Assert.assertTrue(resultObj.equals("bla"));
  }

  @Test
  public void testVarIsEmptyStringl() throws Exception {
 //   Object resultObj = run("GETORELSE(nonexistant,alert_kv)", ImmutableMap.of( "nonexistant", null, "alert_kv", alertNoMatch));
    Object resultObj = StellarProcessorUtils.run("GETORELSE(nonexistant,'bla')",ImmutableMap.of( "nonexistant", "", "alert_kv", alertMatch),context);

    Assert.assertTrue(resultObj != null);
    Assert.assertTrue(resultObj.equals("bla"));
  }

  @Test
  public void testVarIsEmptyMap() throws Exception {

    Map emptyMap = new HashMap<String,String>();
    Object resultObj = StellarProcessorUtils.run("GETORELSE(empty_map,'bla')",ImmutableMap.of( "empty_map", emptyMap),context);

    Assert.assertTrue(resultObj != null);
    Assert.assertTrue(resultObj.equals("bla"));
  }

  @Test
  public void testVarIsNull() throws Exception {

    HashMap contextMap = new HashMap<String,Object>() {{put("empty_map", null);}};
    Object resultObj = StellarProcessorUtils.run("GETORELSE(empty_map,'bla')", contextMap, context);

    Assert.assertTrue(resultObj != null);
    Assert.assertTrue(resultObj.equals("bla"));
  }


  public Object run(String rule, Map<String, Object> variables) throws Exception {
    StellarProcessor processor = new StellarProcessor();
    return processor.parse(rule, new DefaultVariableResolver(x -> variables.get(x),x -> variables.containsKey(x)), StellarFunctions.FUNCTION_RESOLVER(), context);
  }

}