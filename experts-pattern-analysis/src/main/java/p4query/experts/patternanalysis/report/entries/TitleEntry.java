package p4query.experts.patternanalysis.report.entries;

import p4query.experts.patternanalysis.report.Severity;

public class TitleEntry extends Entry {

    public TitleEntry(String message) {
        super(Severity.INFO, message);
    }

    @Override
    public String toString() {
        return "<h3>" + getMessage() + "</h3>\n";
    }
}
