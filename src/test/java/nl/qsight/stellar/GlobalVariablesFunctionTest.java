package nl.qsight.stellar;

import com.google.common.collect.ImmutableMap;
import org.apache.metron.stellar.common.StellarProcessor;
import org.apache.metron.stellar.dsl.Context;
import org.apache.metron.stellar.dsl.DefaultVariableResolver;
import org.apache.metron.stellar.dsl.StellarFunctions;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

public class GlobalVariablesFunctionTest {

    private static Context context;

    @Before
    public void setup() throws Exception {

        context = new Context.Builder()
                .with(Context.Capabilities.GLOBAL_CONFIG
                        , () -> ImmutableMap.of("key1", "value1"
                                , "key2", "value2"
                        )
                )
                .build();
    }

    @Test
    public void testGlobalVariableGet() throws Exception {
        Object result = run("GET_GLOBAL_VAR('key1')", new HashMap<>());
        Assert.assertEquals((String) result, "value1");
    }

    public Object run(String rule, Map<String, Object> variables) throws Exception {
        StellarProcessor processor = new StellarProcessor();
        return processor.parse(rule, new DefaultVariableResolver(x -> variables.get(x),x -> variables.containsKey(x)), StellarFunctions.FUNCTION_RESOLVER(), context);
    }
}