package nl.qsight.stellar;

import org.adrianwalker.multilinestring.Multiline;
import org.apache.commons.collections.map.HashedMap;
import org.apache.log4j.Logger;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.junit.Assert;
import org.junit.Test;

import static org.apache.metron.common.utils.StellarProcessorUtils.run;

public class ExtractValuesTest {

    /**
     * {"loc":"9119460","dst":"185.70.112.55","ip_dst_port":"443","xlatesport":"0","rule":"172","rule_uid":"{C442EE61-863A-4DC9-8E06-0CF499206577}","protocol":"tcp","has_accounting":"1","ip_dst_addr":"185.70.112.55","original_string":"customer=icsdie|loc=9119460|time=2017-06-28 10:54:42|action=accept|orig=185.70.112.7|i\/f_dir=outbound|i\/f_name=eth1|has_accounting=1|product=VPN-1 & FireWall-1|inzone=External|outzone=Internal|rule=172|rule_uid={C442EE61-863A-4DC9-8E06-0CF499206577}|rule_name=prod - nl portal|service_id=https|src=92.109.20.140|s_port=50775|dst=185.70.112.55|service=443|proto=tcp|xlatedst=172.30.201.104|xlatesport=0|xlatedport=0|NAT_rulenum=309|NAT_addtnl_rulenum=1","service_id":"https","action":"accept","NAT_addtnl_rulenum":"1","ip_src_addr":"92.109.20.140","timestamp":1498640082000,"s_port":"50775","xlatedst":"172.30.201.104","i\/f_dir":"outbound","product":"VPN-1 & FireWall-1","inzone":"External","rule_name":"prod - nl portal","src":"92.109.20.140","NAT_rulenum":"309","outzone":"Internal","source.type":"checkpoint_lea","ip_src_port":"50775","orig":"185.70.112.7","i\/f_name":"eth1","service":"443","proto":"tcp","xlatedport":"0","guid":"cf6e3e9a-5526-4354-b82d-19232a2b26be","time":"2017-06-28 10:54:42","customer":"icsdie"}
     */
    @Multiline
    private String event;


    @Test
    public void testExtractValues() throws Exception {

    }
}