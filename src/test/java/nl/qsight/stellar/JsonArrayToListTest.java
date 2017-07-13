package nl.qsight.stellar;

import org.adrianwalker.multilinestring.Multiline;
import org.apache.commons.collections.map.HashedMap;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.junit.Assert;
import org.junit.Test;

import java.util.List;

import static org.apache.metron.common.utils.StellarProcessorUtils.run;

public class JsonArrayToListTest {

    /** {
     "rules": [{
     "ip_src_addr": "10.10.20.10",
     "ip_dst_addr.include.range": "192.168.0.0/24",
     "reason": "Cannot fix the application",
     "new_risk": "4",
     "order": "3"
     },{"ip_src_addr.include": "169.10.34.56",
     "ip_dst_addr.exclude": "192.168.0.10",
     "ip_dst_port.include.list": "(8010,8012,9046)",
     "user.include.list": "(admin,supervisor)",
     "protocol": "tcp",
     "time": {},
     "reason": "Allow risk, just for logging",
     "new_risk": "1",
     "order": "4"
     }]
     }*/
    @Multiline
    private String rulesJsonAsString;



    @Test
    public void testJsonArrayToList() throws Exception {
        StringBuilder sb = new StringBuilder();
        sb.append("JSONARRAY_TOLIST('")
                .append(rulesJsonAsString)
                .append("','rules'").append(')');

        //Stellar parser does not like newlines
        Object res = run(sb.toString().replaceAll("\n",""),new HashedMap());
        List<String> rulesList = (List<String>) res;

        Assert.assertTrue(rulesList.size() == 2);
        String rule1String = rulesList.get(0);

        JSONParser jsonParser = new JSONParser();
        JSONObject rule1 = (JSONObject) jsonParser.parse(rule1String);

        Assert.assertTrue(rule1.get("ip_src_addr") != null);
        Assert.assertTrue(rule1.get("ip_src_addr").equals("10.10.20.10"));
    }

}
