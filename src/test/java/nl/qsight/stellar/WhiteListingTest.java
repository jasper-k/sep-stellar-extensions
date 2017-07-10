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

//import static org.apache.metron.common.utils.StellarProcessorUtils.run;

public class WhiteListingTest {

    /**
     {
     "ip_src_addr.include": "10.10.10.10",
     "ip_dst_port.exclude": "1212",
     "protocol.exclude": "tcp",
     "time.include.range": "0 23 * 6 2-6|11H",
     "wl_reason": "Allow risk, just for logging",
     "wl_new_risk": "1",
     "wl_order": "4"
     }
     */
    @Multiline
    private String rule;


    private Map<String,String> alertFieldsAndValues = new HashMap<String,String>() {{put("ip_dst_port","1213");
                                                                                     put("protocol","udp");
                                                                                     put("ip_src_addr","10.10.10.10");
                                                                                     put("timestamp","1498640504554");
                                                                                }};
    private List<String> mockList = new ArrayList<>();

    private static Context context;
    private static final String EXTRACT_FIELDS_KEY = "sep.whitelist.extract.fields";

    @Before

    public void setup() throws Exception {

        context = new Context.Builder()
                .with( Context.Capabilities.GLOBAL_CONFIG
                        , () -> ImmutableMap.of(EXTRACT_FIELDS_KEY
                                , "'_ip_dst_port',ip_dst_port,'_code',code,'_ip_dst_addr',ip_dst_addr,'_timestamp',timestamp,'_protocol',protocol"
                                , "protocol"
                                , "TCP"
                        )
                )
                .build();
    }

    @Test
    public void testExtractValues() throws Exception {

        Object remapRes = run("LIST_OF_FIELDS_AND_KEYS_TO_MAP(mockList)", ImmutableMap.of("mockList", mockList));
        Object resultObj = run("IS_WHITELISTED(alert_kv,rule)", ImmutableMap.of("alert_kv", alertFieldsAndValues , "rule", rule));

        //Return object = null when NOT whitelisted, a JSONObject (Map) when whitelisted
        JSONObject whiteListReason = (JSONObject) resultObj;
        Assert.assertTrue(whiteListReason != null);
        Assert.assertTrue(whiteListReason.containsKey("wl_order"));

    }

    public Object run(String rule, Map<String, Object> variables) throws Exception {
        StellarProcessor processor = new StellarProcessor();
        return processor.parse(rule, x -> variables.get(x), StellarFunctions.FUNCTION_RESOLVER(), context);
    }

}