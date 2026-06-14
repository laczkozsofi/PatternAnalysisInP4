package p4query.experts.patternanalysis.analyses;

import java.util.List;
import java.util.Map;

import org.apache.tinkerpop.gremlin.process.traversal.dsl.graph.GraphTraversal;
import org.apache.tinkerpop.gremlin.process.traversal.dsl.graph.GraphTraversalSource;
import org.apache.tinkerpop.gremlin.process.traversal.dsl.graph.__;
import org.apache.tinkerpop.gremlin.structure.Vertex;

import p4query.experts.patternanalysis.report.Report;
import p4query.experts.patternanalysis.report.Section;
import p4query.experts.patternanalysis.report.Severity;
import p4query.experts.patternanalysis.report.entries.Entry;
import p4query.experts.patternanalysis.report.entries.ErrorEntry;
import p4query.experts.patternanalysis.report.entries.ScoreEntry;

public class SelectStatementAnalysis extends AnalysisBase {

    public SelectStatementAnalysis(Report report) {
        super(report);
        section = new Section("Select statement");
    }

    @Override
    public void analyse(GraphTraversalSource g) {
        System.out.println("***Select statement***");
        GraphTraversal<Vertex, Vertex> selectStatements = g.V().has("class", "SelectExpressionContext");
        // last key is not "DEFAULT"
        List<Map<Object, Object>> wrongSelectStatements = selectStatements.filter(
                __.out().has("class", "SelectCaseListContext").filter(
                        __.out().has("class", "SelectCaseContext").filter(
                                __.out().has("class", "KeysetExpressionContext")
                                        .repeat(__.out()).until(__.not(__.out())).filter(__.inE()
                                                .values("rule").not(__.is("DEFAULT"))))))
                .valueMap("nodeId", "line").toList();
        if (wrongSelectStatements.isEmpty()) {
            System.out.println("OK");
            section.addEntry(new Entry(Severity.INFO, "Ok"));
        } else {
            wrongSelectStatements.forEach(x -> {
                System.out.println(x);
                section.addEntry(new ErrorEntry(Severity.WARNING, "The last branch of select statement is not the 'default' branch", getLineNumber(x.get("line"))));
                changeScore(-1);
                section.addEntry(new ScoreEntry(-1));
            });
        }

        report.addSection(section);
    }

    String getLineNumber(Object list) {
        try {
            return (String)((List<?>) list).get(0);
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }
    }

}
