package p4query.experts.patternanalysis.report;

import java.util.ArrayList;
import java.util.List;

import p4query.experts.patternanalysis.report.entries.Entry;

public class Section {
    private String title;

    private List<Entry> entries = new ArrayList<>();

    public Section(String title) {
        this.title = title;
    }

    public void addEntry(Entry entry) {
        entries.add(entry);
    }

    public List<Entry> getEntries() {
        return entries;
    }

    public String getTitle() {
        return title;
    }

}
