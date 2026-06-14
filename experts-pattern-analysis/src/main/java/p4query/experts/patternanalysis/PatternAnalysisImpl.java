package p4query.experts.patternanalysis;

import org.codejargon.feather.Provides;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import javax.inject.Provider;
import javax.inject.Singleton;

import org.apache.tinkerpop.gremlin.process.traversal.dsl.graph.GraphTraversalSource;
import p4query.ontology.providers.AppUI;
import p4query.ontology.providers.CLIArgs;
import p4query.ontology.providers.P4FileProvider.InputP4File;
import p4query.ontology.analyses.SyntaxTree;
import p4query.ontology.analyses.ControlFlow;
import p4query.ontology.analyses.PatternAnalysis;
import p4query.applications.patternanalysis.PatternCommand;
import p4query.experts.patternanalysis.analyses.AnalysisBase;
import p4query.experts.patternanalysis.analyses.HeaderStatusAnalysis;
import p4query.experts.patternanalysis.analyses.KnownHeadersAnalysis;
import p4query.experts.patternanalysis.analyses.ReturnStatementAnalysis;
import p4query.experts.patternanalysis.analyses.SelectStatementAnalysis;
import p4query.experts.patternanalysis.report.HtmlGenerator;
import p4query.experts.patternanalysis.report.Report;
import p4query.experts.patternanalysis.report.Section;
import p4query.experts.patternanalysis.report.Severity;
import p4query.experts.patternanalysis.report.entries.Entry;
import p4query.ontology.Status;

public class PatternAnalysisImpl {

    private static final Logger LOGGER = LoggerFactory.getLogger(PatternAnalysisImpl.class);

    @Provides
    @Singleton
    @PatternAnalysis
    public Status analyse(GraphTraversalSource g,
            @SyntaxTree Provider<Status> ensureSt,
            @ControlFlow Provider<Status> ensureCf,
            @CLIArgs AppUI args,
            @InputP4File File inputP4) {
        if (g.V().count().next() == 0) {
            ensureSt.get();
        }
        ensureCf.get();

        long startTime = System.currentTimeMillis();
        LOGGER.info("{} started.", PatternAnalysis.class.getSimpleName());
        System.out.println("************PatterAnalysis start*************");

        String headersStruct = null;
        String headersFile = null;
        if (args instanceof PatternCommand) {
            headersStruct = ((PatternCommand) args).headersStruct;
            headersFile = ((PatternCommand) args).headersFile;
        }

        int totalScore = 0;
        Report report = new Report("Results of Pattern Analysis");

        List<AnalysisBase> analyses = List.of(new SelectStatementAnalysis(report), new ReturnStatementAnalysis(report),
                new HeaderStatusAnalysis(report, headersStruct), new KnownHeadersAnalysis(report, headersFile, headersStruct));

        for (AnalysisBase analysis : analyses) {
            analysis.analyse(g);
            int score = analysis.getScore();
            totalScore += score;
            System.out.println("Score: " + score);
        }

        writeTotalScore(totalScore, report);

        String html = new HtmlGenerator().generate(report);
        try {
            Path reportPath = Files.writeString(Path.of("report.html"), html);
            LOGGER.info("The report is generated: {}", reportPath);
        } catch (IOException e) {
            e.printStackTrace();
        }

        System.out.println("************PatterAnalysis done*************");
        long stopTime = System.currentTimeMillis();
        LOGGER.info("{} complete. Time used: {} ms.", PatternAnalysis.class.getSimpleName() , stopTime - startTime);
        return new Status();
    }

    private void writeTotalScore(int totalScore, Report report) {
        System.out.println("===========");
        System.out.println("Total score: " + totalScore);

        Section section = new Section("Total score");
        section.addEntry(new Entry(Severity.INFO, String.valueOf(totalScore)));
        report.addSection(section);

    }

}
