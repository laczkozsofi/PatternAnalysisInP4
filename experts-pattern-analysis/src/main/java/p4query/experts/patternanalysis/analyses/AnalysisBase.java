package p4query.experts.patternanalysis.analyses;

import org.apache.tinkerpop.gremlin.process.traversal.dsl.graph.GraphTraversalSource;

import p4query.experts.patternanalysis.report.Report;
import p4query.experts.patternanalysis.report.Section;

public abstract class AnalysisBase {
    private int score = 0;
    protected Report report;
    protected Section section;

    public AnalysisBase(Report report) {
        this.report = report;
    }

    public int getScore() {
        return score;
    }

    protected void changeScore(int x) {
        score = score + x;
    }

    public abstract void analyse(GraphTraversalSource g);
}
