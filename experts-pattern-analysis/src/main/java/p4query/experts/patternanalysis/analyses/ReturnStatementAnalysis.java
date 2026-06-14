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

public class ReturnStatementAnalysis extends AnalysisBase {

    public ReturnStatementAnalysis(Report report) {
        super(report);
        section = new Section("Return statement");
    }

    @Override
    public void analyse(GraphTraversalSource g) {
        System.out.println("***Return statement***");
        GraphTraversal<Vertex, Vertex> returnStatements = g.V().has("class", "ReturnStatementContext");
        List<Map<Object, Object>> returnStatementsWithCodeAfter = returnStatements.filter(
                __.in().has("class", "StatementContext")
                        .in().has("class", "StatementOrDeclarationContext")
                        .in().has("class", "StatOrDeclListContext")
                        .in().has("class", "StatOrDeclListContext"))
                .valueMap("nodeId", "line").toList();

        if (returnStatementsWithCodeAfter.isEmpty()) {
            System.out.println("OK");
            section.addEntry(new Entry(Severity.INFO, "Ok"));
        } else {
            returnStatementsWithCodeAfter.forEach(x -> {
                System.out.println(x);
                section.addEntry(new ErrorEntry(Severity.WARNING, "Code is found after a return statement.", getLineNumber(x.get("line"))));
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
