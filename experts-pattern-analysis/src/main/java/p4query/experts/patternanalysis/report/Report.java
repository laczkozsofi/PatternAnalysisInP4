package p4query.experts.patternanalysis.report;

import java.util.ArrayList;
import java.util.List;

public class Report {
    private String title;
    private List<Section> sections = new ArrayList<>();

    public Report(String title) {
        this.title = title;
    }

    public void addSection(Section section) {
        sections.add(section);
    }

    public List<Section> getSections() {
        return sections;
    }

    public String getTitle() {
        return title;
    }
}
