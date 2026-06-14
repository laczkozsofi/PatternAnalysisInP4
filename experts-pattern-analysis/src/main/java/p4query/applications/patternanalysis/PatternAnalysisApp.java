package p4query.applications.patternanalysis;

import java.io.File;

import javax.inject.Inject;
import javax.inject.Provider;

import org.apache.tinkerpop.gremlin.process.traversal.dsl.graph.GraphTraversalSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import p4query.ontology.Status;
import p4query.ontology.analyses.ControlFlow;
import p4query.ontology.analyses.PatternAnalysis;
import p4query.ontology.analyses.SyntaxTree;
import p4query.ontology.providers.AppUI;
import p4query.ontology.providers.Application;
import p4query.ontology.providers.CLIArgs;

public class PatternAnalysisApp implements Application {
    private static final Logger LOGGER = LoggerFactory.getLogger(PatternAnalysisApp.class);
    private final PatternCommand cmd = new PatternCommand();

    @Override
    public AppUI getUI() {
        return cmd;
    }

    @Inject
    private GraphTraversalSource g;

    @Inject
    @SyntaxTree
    private Provider<Status> st;
    @Inject
    @ControlFlow
    private Provider<Status> cfg;
    @Inject
    @PatternAnalysis
    private Provider<Status> pa;

    @Inject
    @CLIArgs
    private AppUI cli;

    @Override
    public Status run() throws Exception {
        long startTimeApp = System.currentTimeMillis();
        LOGGER.info("Pattern analysis application started: {}", cli);
        st.get();
        cfg.get();
        pa.get();

        long stopTimeApp = System.currentTimeMillis();
        LOGGER.info("Application complete. Time used: {} ms.", stopTimeApp - startTimeApp);
        return new Status();

    }

}
