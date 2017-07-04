package nl.qsight.stellar;

import org.adrianwalker.multilinestring.Multiline;
import org.apache.commons.collections.map.HashedMap;
import org.apache.log4j.Logger;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.junit.Assert;
import org.junit.Test;

import static org.apache.metron.common.utils.StellarProcessorUtils.run;
import static org.apache.metron.common.utils.StellarProcessorUtils.runPredicate;

public class JsonArrayToListTest {

    /** {
     "rules": [{
     "source_ip": "10.10.20.10",
     "destination_ip.include": "192.168.0.0/24",
     "reason": "Cant fix the application",
     "new_risk": "4",
     "order": "3"
     },{"source_ip": {},
     "destination_ip.exclude": "192.168.0.10",
     "user": "admin",
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
        Object res = run(sb.toString().replaceAll("(\n|\\s)",""),new HashedMap());
        JSONArray rulesJSONArray = (JSONArray) res;
        Assert.assertTrue(rulesJSONArray.size() == 2);
        JSONObject rule1 = (JSONObject) rulesJSONArray.get(0);
        Assert.assertTrue(rule1.get("source_ip") != null);
        Assert.assertTrue(((String) rule1.get("source_ip")).equals("10.10.20.10"));
    }

}
