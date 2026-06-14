package p4query.experts.patternanalysis.report.entries;

import p4query.experts.patternanalysis.report.Severity;

public class ErrorEntry extends Entry {
    private Object line;

    public ErrorEntry(Severity severity, String message, Object line) {
        super(severity, message);
        this.line = line;
    }

    public Object getLine() {
        return line;
    }

    public void setLine(Object line) {
        this.line = line;
    }

    @Override
    public String toString() {
        return getSeverity() + " -> " + getMessage() + " (line: " + getLine() + ")\n";
    }
}
