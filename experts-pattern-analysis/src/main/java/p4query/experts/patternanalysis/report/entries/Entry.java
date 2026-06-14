package p4query.experts.patternanalysis.report.entries;

import p4query.experts.patternanalysis.report.Severity;

public class Entry {
    private Severity severity;
    private String message;

    public Entry() {}

    public Entry(Severity severity, String message) {
        this.severity = severity;
        this.message = message;
    }

    public Severity getSeverity() {
        return severity;
    }

    public void setSeverity(Severity severity) {
        this.severity = severity;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    @Override
    public String toString() {
        return getMessage() + "\n";
    }
    
}
