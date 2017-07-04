package nl.qsight.stellar;

/**
 * Created by jknulst on 6/28/17.
 */
public class WhitelistTimeRangeParsingException extends Exception {
    static final long serialVersionUID = 7816675828146070155L;

    public WhitelistTimeRangeParsingException(String reason) {
        super(reason);
    }
    public WhitelistTimeRangeParsingException(String reason, Throwable t) {
        super(reason, t);
    }
}

