package nl.qsight.stellar;

import com.google.common.collect.ImmutableMap;
import org.adrianwalker.multilinestring.Multiline;
import org.apache.metron.common.dsl.Context;
import org.apache.metron.common.dsl.StellarFunctions;
import org.apache.metron.common.stellar.StellarProcessor;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

public class ExtractValuesTest {

    /**
     * {"loc":"9119460","dst":"185.70.112.55","ip_dst_port":"443","xlatesport":"0","rule":"172","rule_uid":"{C442EE61-863A-4DC9-8E06-0CF499206577}","protocol":"tcp","has_accounting":"1","ip_dst_addr":"185.70.112.55","original_string":"customer=icsdie|loc=9119460|time=2017-06-28 10:54:42|action=accept|orig=185.70.112.7|i\/f_dir=outbound|i\/f_name=eth1|has_accounting=1|product=VPN-1 & FireWall-1|inzone=External|outzone=Internal|rule=172|rule_uid={C442EE61-863A-4DC9-8E06-0CF499206577}|rule_name=prod - nl portal|service_id=https|src=92.109.20.140|s_port=50775|dst=185.70.112.55|service=443|proto=tcp|xlatedst=172.30.201.104|xlatesport=0|xlatedport=0|NAT_rulenum=309|NAT_addtnl_rulenum=1","service_id":"https","action":"accept","NAT_addtnl_rulenum":"1","ip_src_addr":"92.109.20.140","timestamp":1498640082000,"s_port":"50775","xlatedst":"172.30.201.104","i\/f_dir":"outbound","product":"VPN-1 & FireWall-1","inzone":"External","rule_name":"prod - nl portal","src":"92.109.20.140","NAT_rulenum":"309","outzone":"Internal","source.type":"checkpoint_lea","ip_src_port":"50775","orig":"185.70.112.7","i\/f_name":"eth1","service":"443","proto":"tcp","xlatedport":"0","guid":"cf6e3e9a-5526-4354-b82d-19232a2b26be","time":"2017-06-28 10:54:42","customer":"icsdie"}
     */
    @Multiline
    private String event;

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
    public void testJoinAndSplit() throws Exception {

        Object globalRes = run("GET_GLOBAL_VAR('"+EXTRACT_FIELDS_KEY+"')", new HashMap<>());
        String joinFieldsParam = (String) globalRes;
        Object joinRes = run("JOIN(["+joinFieldsParam+"],'^')", ImmutableMap.of("ip_dst_port", "1111", "protocol", "UDP", "ip_dst_addr","185.70.112.55", "timestamp","1498640504554"));

        String joinedFields = (String) joinRes;
        Object splitRes = run("SPLIT('"+joinedFields+"','^')", new HashMap<>());
        ArrayList<String> fieldValueList = (ArrayList<String>) splitRes;

        Object remapRes = run("LIST_OF_FIELDS_AND_KEYS_TO_MAP(SPLIT('"+joinedFields+"','^'))", new HashMap<>());
        Map<String,String> mappedFields = (Map<String,String>) remapRes;

        Assert.assertTrue(mappedFields.containsValue("185.70.112.55"));
        Assert.assertTrue(mappedFields.containsValue("1498640504554"));
        Assert.assertTrue(mappedFields.keySet().size()==4);
    }

    public Object run(String rule, Map<String, Object> variables) throws Exception {
        StellarProcessor processor = new StellarProcessor();
        return processor.parse(rule, x -> variables.get(x), StellarFunctions.FUNCTION_RESOLVER(), context);
    }

}