package nl.qsight.stellar;


import com.google.common.collect.ImmutableMap;
import org.adrianwalker.multilinestring.Multiline;
import org.apache.metron.stellar.common.StellarProcessor;
import org.apache.metron.stellar.dsl.Context;
import org.apache.metron.stellar.dsl.DefaultVariableResolver;
import org.apache.metron.stellar.dsl.StellarFunctions;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;


public class OrdinalTest {

    private static Context context;
    private static String INPUTLIST;

    /** ["ip_src_addr": "10.10.20.10",
     "ip_dst_addr.include.range": "192.168.0.0/24",
     "reason": "Cannot fix the application",
     "new_priority": "4",
     "order": "3"
     },{"ip_src_addr.include": "169.10.34.56",
     "ip_dst_addr.exclude": "192.168.0.10",
     "ip_dst_port.include.list": "(8010,8012,9046)",
     "user.include.list": "(admin,supervisor)",
     "protocol": "tcp",
     "time": {},
     "reason": "Allow risk, just for logging",
     "new_priority": "1",
     "order": "4"
     }]
     }*/
    @Multiline
    private String rulesJsonAsString;

    @Before
    public void setup() throws Exception {
        context = new Context.Builder()
                .with( Context.Capabilities.GLOBAL_CONFIG
                        , () -> ImmutableMap.of("bla"
                                , "'_ip_src_addr',ip_src_addr,'_ip_dst_addr',ip_dst_addr,'_ip_src_port',ip_src_port,'_ip_dst_port',ip_dst_port,'_protocol',protocol,'_user',user,'_timestamp',timestamp"
                        )
                )
                .build();
    }


    @Test
    public void testMaxOfStringList() throws Exception {

        List<Object> inputList = new ArrayList<Object>(){{
            add("value3");
            add("value1");
            add("23");
            add("value2");
        }};

        //Stellar parser does not like newlines
        Object res = run("MAX(input_list)",ImmutableMap.of("input_list", inputList));

        Assert.assertNotNull(res);
        Assert.assertTrue(res.equals("value3"));
    }

    @Test
    public void testMaxOfIntegerList() throws Exception {

        List<Object> inputList = new ArrayList<Object>(){{
            add(12);
            add(56);
        }};

        //Stellar parser does not like newlines
        Object res = run("MAX(input_list)",ImmutableMap.of("input_list", inputList));

        Assert.assertNotNull(res);
        Assert.assertTrue(res.equals(56));
    }

    @Test
    public void testMaxOfNullInList() throws Exception {

        List<Object> inputList = new ArrayList<Object>(){{
            add(145);
            add(null);
        }};

        //Stellar parser does not like newlines
        Object res = run("MAX(input_list)",ImmutableMap.of("input_list", inputList));

        Assert.assertNotNull(res);
        Assert.assertTrue(res.equals(145));
    }

    @Test
    public void testAllNullList() throws Exception {

        List<Object> inputList = new ArrayList<Object>(){{
            add(null);
            add(null);
        }};

        //Stellar parser does not like newlines
        Object res = run("MAX(input_list)",ImmutableMap.of("input_list", inputList));

        Assert.assertNull(res);
    }

    @Test
    public void testMinOfIntegerList() throws Exception {

        List<Object> inputList = new ArrayList<Object>(){{
            add(56);
            add(12);
            add(23);
            add(null);
        }};

        //Stellar parser does not like newlines
        Object res = run("MIN(input_list)",ImmutableMap.of("input_list", inputList));

        Assert.assertNotNull(res);
        Assert.assertTrue(res.equals(12));
    }


    @Test
    public void testMaxOfLongList() throws Exception {

        List<Object> inputList = new ArrayList<Object>(){{
            add(12L);
            add(56L);
            add(457L);
        }};

        //Stellar parser does not like newlines
        Object res = run("MAX(input_list)",ImmutableMap.of("input_list", inputList));

        Assert.assertNotNull(res);
        Assert.assertTrue(res.equals(457L));
    }

    @Test(expected = IllegalStateException.class)
    public void testMaxOfMixedList() throws Exception {

        List<Object> inputList = new ArrayList<Object>(){{
            add(12);
            add("string");
            add(457L);
        }};

        //Stellar parser does not like newlines
        Object res = run("MAX(input_list)",ImmutableMap.of("input_list", inputList));

    }

    public Object run(String rule, Map<String, Object> variables) throws Exception {
        StellarProcessor processor = new StellarProcessor();
        return processor.parse(rule, new DefaultVariableResolver(x -> variables.get(x), x -> variables.containsKey(x)), StellarFunctions.FUNCTION_RESOLVER(), context);
    }

}
