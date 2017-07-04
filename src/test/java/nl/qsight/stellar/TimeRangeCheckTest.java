package nl.qsight.stellar;

import org.adrianwalker.multilinestring.Multiline;
import org.apache.commons.collections.map.HashedMap;
import org.junit.Assert;
import org.junit.Test;

import static org.apache.metron.common.utils.StellarProcessorUtils.run;
import static org.apache.metron.common.utils.StellarProcessorUtils.runPredicate;

public class TimeRangeCheckTest {

    /**1498640504554*/
    @Multiline
    private String metronEventTs;


    /**'{"cron" : "0 23 * 6 2-6","duration":"8","duration_unit":"H","start_date":"23-06-2015","end_date":"28-12-2016"}'*/
    @Multiline
    private String inputRangeDefinition;



    @Test
    public void testTimeRangeChecker() throws Exception {
        StringBuilder sb = new StringBuilder();
        sb.append("IN_TIME_RANGE('")
                .append(metronEventTs)
                .append("',")
                .append(inputRangeDefinition).append(')');
        Object res = run(sb.toString(),new HashedMap());
        Assert.assertTrue((Boolean) res);
    }

}
