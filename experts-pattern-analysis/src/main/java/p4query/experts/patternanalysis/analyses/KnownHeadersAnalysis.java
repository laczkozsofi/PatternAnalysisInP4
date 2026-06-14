package p4query.experts.patternanalysis.analyses;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Scanner;

import org.apache.tinkerpop.gremlin.process.traversal.dsl.graph.GraphTraversalSource;
import org.apache.tinkerpop.gremlin.process.traversal.dsl.graph.__;

import p4query.experts.patternanalysis.report.Report;
import p4query.experts.patternanalysis.report.Section;
import p4query.experts.patternanalysis.report.Severity;
import p4query.experts.patternanalysis.report.entries.Entry;
import p4query.experts.patternanalysis.report.entries.ScoreEntry;

public class KnownHeadersAnalysis extends AnalysisBase {

    private String headerFilePath = "experts-pattern-analysis\\src\\main\\resources\\headers.txt";
    private String headersStructName = "headers";

    public KnownHeadersAnalysis(Report report, String headerFilePath, String headersStructName) {
        super(report);
        section = new Section("Known headers");

        if (headerFilePath != null) {
            this.headerFilePath = headerFilePath;
        }

        if (headersStructName != null) {
            this.headersStructName = headersStructName;
        }

    }

    @Override
    public void analyse(GraphTraversalSource g) {
        System.out.println("***Known headers***");

        Map<Object, List<Integer>> headerFields = getHeaderFields(g);
        Map<Object, List<Integer>> usedHeaders = getHeaders(g, headerFields);

        System.out.println("headers" + usedHeaders);

        String absoluteHeaderFilePath = absolutePath(headerFilePath);
        Map<String, List<Integer>> knownHeaders = readHeadersFile(absoluteHeaderFilePath);

        checkUsedHeaders(usedHeaders, knownHeaders);

        report.addSection(section);
    }

    private Map<Object, List<Integer>> getHeaderFields(GraphTraversalSource g) {
        Map<Object, List<Integer>> headerFields = new HashMap<>();

        List<Object> headerTypeDeclarations = g.V().has("class", "TypeDeclarationContext")
                .out().has("class", "DerivedTypeDeclarationContext")
                .out().has("class", "HeaderTypeDeclarationContext")
                .values("nodeId").toList();
        for (Object decl : headerTypeDeclarations) {
            List<Object> headerName = g.V().has("nodeId", decl)
                    .out().has("class", "NameContext")
                    .repeat(__.out()).until(__.not(__.out())).values("value").toList();
            if (!headerName.isEmpty()) {
                List<Object> headerFieldsTypeRef = g.V().has("nodeId", decl)
                        .out().has("class", "StructFieldListContext")
                        .repeat(
                                __.outE("syn")
                                        .inV())
                        .emit().dedup().has("class", "TypeRefContext")
                        .values("nodeId").toList();
                List<Integer> lengthOfFields = getLengthOfFields(g, headerFieldsTypeRef);
                headerFields.put(headerName.get(0), lengthOfFields);
            }
        }

        return headerFields;
    }

    private List<Integer> getLengthOfFields(GraphTraversalSource g, List<Object> headerFieldsTypeRef) {
        List<Integer> list = new ArrayList<>();
        for (Object object : headerFieldsTypeRef) {
            list.add(getLengthFromTypeRef(g, object));
        }
        return list;
    }

    private Integer getLengthFromTypeRef(GraphTraversalSource g, Object typeRef) {
        List<Object> baseTypeContext = g.V().has("nodeId", typeRef).outE().has("rule", "baseType").inV()
                .values("nodeId")
                .toList();
        if (!baseTypeContext.isEmpty()) {
            return getLengthFromBaseType(g, baseTypeContext.get(0));
        } else {
            List<Object> typeNameContext = g.V().has("nodeId", typeRef).outE().has("rule", "typeName").inV()
                    .values("nodeId").toList();
            if (!typeNameContext.isEmpty()) {
                return getLengthFromTypeName(g, typeNameContext.get(0));
            }
        }
        return null;
    }

    private Integer getLengthFromBaseType(GraphTraversalSource g, Object object) {
        List<Object> value = g.V().has("nodeId", object).outE().has("rule", "INTEGER").inV().values("value").toList();
        List<Object> bit = g.V().has("nodeId", object).outE().has("rule", "BIT").inV().values("value").toList();
        if (!bit.isEmpty() && "bit".equals(bit.get(0)) && !value.isEmpty()) {
            return Integer.valueOf((String) value.get(0));
        }
        return null;
    }

    private Integer getLengthFromTypeName(GraphTraversalSource g, Object object) {
        List<Object> name = g.V().has("nodeId", object).repeat(__.out()).until(__.not(__.out())).values("value")
                .toList();
        if (!name.isEmpty()) {
            List<Object> declContextTypeRef = g.V().has("class", "TypedefDeclarationContext").filter(
                    __.outE().has("rule", "name").inV()
                            .repeat(__.out()).until(__.not(__.out())).has("value", name.get(0)))
                    .outE().has("rule", "typeRef").inV()
                    .values("nodeId").toList();
            if (!declContextTypeRef.isEmpty()) {
                return getLengthFromTypeRef(g, declContextTypeRef.get(0));
            }
        }
        return null;
    }

    private Map<Object, List<Integer>> getHeaders(GraphTraversalSource g, Map<Object, List<Integer>> headerTypes) {
        Map<Object, List<Integer>> headers = new HashMap<>();
        List<Object> structFieldContexts = g.V().has("class", "StructTypeDeclarationContext")
                .filter(__.out().has("class", "NameContext").repeat(__.out()).until(__.not(__.out())).has("value",
                        headersStructName))
                .out().has("class", "StructFieldListContext")
                .repeat(
                        __.outE("syn")
                                .inV())
                .emit().dedup().has("class", "StructFieldContext")
                .values("nodeId").toList();
        for (Object structField : structFieldContexts) {
            List<Object> name = g.V().has("nodeId", structField).out().has("class", "NameContext").repeat(__.out())
                    .until(__.not(__.out()))
                    .values("value").toList();
            List<Object> type = g.V().has("nodeId", structField).out().has("class", "TypeRefContext").repeat(__.out())
                    .until(__.not(__.out()))
                    .values("value").toList();
            if (!name.isEmpty() && !type.isEmpty()) {
                headers.put(name.get(0), headerTypes.get(type.get(0)));
            }
        }
        return headers;
    }

    private Map<String, List<Integer>> readHeadersFile(String path) {
        Map<String, List<Integer>> headers = new HashMap<>();

        File file = new File(path);
        try (Scanner reader = new Scanner(file)) {
            while (reader.hasNextLine()) {
                String line = reader.nextLine();
                List<String> list = Arrays.asList(line.split(" "));
                if (list.size() > 0) {
                    List<Integer> intList = list.subList(1, list.size()).stream().map(x -> Integer.valueOf(x)).toList();
                    headers.put(list.get(0), intList);
                }
            }
        } catch (FileNotFoundException e) {
            System.out.println("Could not open file: " + file.getPath());
            e.printStackTrace();
        }
        System.out.println(headers);

        return headers;
    }

    private void checkUsedHeaders(Map<Object, List<Integer>> usedHeaders, Map<String, List<Integer>> knownHeaders) {
        for (Object key : usedHeaders.keySet()) {
            System.out.println("key: " + key);
            List<Integer> used = usedHeaders.get(key);
            List<Integer> known = knownHeaders.get(key);
            System.out.println("used: " + used);
            System.out.println("known: " + known);
            if (used != null && known != null) {
                if (checkIntegerLists(usedHeaders.get(key), knownHeaders.get(key))) {
                    section.addEntry(new Entry(Severity.INFO, key + " header is applied correctly"));
                    section.addEntry(new ScoreEntry(3));
                    changeScore(3);
                } else {
                    section.addEntry(new Entry(Severity.INFO, key + " header is not applied correctly"));
                    section.addEntry(new ScoreEntry(-3));
                    changeScore(-3);
                }
            }
        }
    }

    private boolean checkIntegerLists(List<Integer> used, List<Integer> known) {
        if (used != null && known != null && used.size() == known.size()) {
            List<Integer> usedSorted = new ArrayList<>(used);
            List<Integer> knownSorted = new ArrayList<>(known);

            Collections.sort(usedSorted);
            Collections.sort(knownSorted);

            return usedSorted.equals(knownSorted);
        } else {
            return false;
        }
    }

    private String absolutePath(String relativePath) {
        File b = new File(relativePath);

        try {
            return b.getCanonicalPath();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }
}
