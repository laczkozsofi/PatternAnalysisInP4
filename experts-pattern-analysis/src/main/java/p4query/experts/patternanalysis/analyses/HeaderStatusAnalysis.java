package p4query.experts.patternanalysis.analyses;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Stack;
import java.util.StringJoiner;

import org.apache.tinkerpop.gremlin.process.traversal.Path;
import org.apache.tinkerpop.gremlin.process.traversal.dsl.graph.GraphTraversal;
import org.apache.tinkerpop.gremlin.process.traversal.dsl.graph.GraphTraversalSource;
import org.apache.tinkerpop.gremlin.process.traversal.dsl.graph.__;
import org.apache.tinkerpop.gremlin.structure.Vertex;

import p4query.experts.patternanalysis.HeaderFieldInfo;
import p4query.experts.patternanalysis.HeaderInfo;
import p4query.experts.patternanalysis.HeaderStatus;
import p4query.experts.patternanalysis.InstructionEffect;
import p4query.experts.patternanalysis.report.Report;
import p4query.experts.patternanalysis.report.Section;
import p4query.experts.patternanalysis.report.Severity;
import p4query.experts.patternanalysis.report.entries.Entry;
import p4query.experts.patternanalysis.report.entries.ErrorEntry;
import p4query.experts.patternanalysis.report.entries.ScoreEntry;
import p4query.experts.patternanalysis.report.entries.TitleEntry;

public class HeaderStatusAnalysis extends AnalysisBase {

    private String headersStructName = "headers";

    public HeaderStatusAnalysis(Report report, String headersStructName) {
        super(report);
        section = new Section("Status of headers ");

        if (headersStructName != null) {
            this.headersStructName = headersStructName;
        }
    }

    @Override
    public void analyse(GraphTraversalSource g) {
        System.out.println("***SetInvalid***");
        Map<Object, List<Object>> headerTypes = getHeaderTypes(g);
        Map<Object, HeaderInfo> headers = getHeaders(g, headerTypes);

        checkParse(g, headers);

        List<Object> controlNames = getControlsOrder(g);
        Map<Object, Object> nodeIdOfControlNames = getNodeIdOfControlNames(g, controlNames);

        Map<Object, List<Object>> controls = getControlsToCheck(g, nodeIdOfControlNames);
        checkControls(g, controls, headers, headerTypes, nodeIdOfControlNames);

        checkDeparse(g, headers);

        report.addSection(section);
    }

    private Map<Object, Object> getNodeIdOfControlNames(GraphTraversalSource g, List<Object> controlNames) {
        Map<Object, Object> controlDeclarations = new LinkedHashMap<>();
        for (Object name : controlNames) {
            List<Object> controlNodeId = g.V().has("class", "ControlDeclarationContext")
                    .filter(
                            __.outE().has("rule", "controlTypeDeclaration").inV()
                                    .outE().has("rule", "name").inV()
                                    .repeat(__.out()).until(__.not(__.out())).has("value", name))
                    .values("nodeId").toList();
            if (!controlNodeId.isEmpty()) {
                controlDeclarations.put(controlNodeId.get(0), name);
            }
        }
        return controlDeclarations;
    }

    private Map<Object, List<Object>> getControlsToCheck(GraphTraversalSource g,
            Map<Object, Object> controlDeclarations) {
        Map<Object, List<Object>> controlDeclarationsWithHeaderParam = new LinkedHashMap<>();

        for (Object controlDeclNodeId : controlDeclarations.keySet()) {
            List<Object> parameterContexts = g.V().has("nodeId", controlDeclNodeId)
                    .outE().has("rule", "controlTypeDeclaration").inV()
                    .outE().has("rule", "parameterList").inV()
                    .repeat(
                            __.outE("syn")
                                    .inV())
                    .emit().dedup().has("class", "ParameterContext")
                    .values("nodeId").toList();

            parameterContexts.removeIf(x -> !headersStructName.equals(getTypeOfParameter(g, x)));
            if (!parameterContexts.isEmpty()) {
                controlDeclarationsWithHeaderParam.put(controlDeclNodeId,
                        parameterContexts.stream().map(x -> getNameOfParameter(g, x)).toList());
            }
        }
        return controlDeclarationsWithHeaderParam;
    }

    private List<Object> getControlsOrder(GraphTraversalSource g) {
        Stack<Object> arguments = new Stack<>();
        List<Object> nonEmptyArgList = g.V().has("class", "InstantiationContext")
                .outE().has("rule", "argumentList").inV()
                .outE().has("rule", "nonEmptyArgList").inV().values("nodeId").toList();
        while (!nonEmptyArgList.isEmpty()) {
            Object nonEmptyArg = nonEmptyArgList.remove(0);
            List<Object> argsContext = g.V().has("nodeId", nonEmptyArg)
                    .outE().has("rule", "argument").inV().values("nodeId").toList();
            if (!argsContext.isEmpty()) {
                arguments.add(argsContext.get(0));
            }
            List<Object> nonEmptyArgListContext = g.V().has("nodeId", nonEmptyArg)
                    .outE().has("rule", "nonEmptyArgList").inV().values("nodeId").toList();
            if (!nonEmptyArgListContext.isEmpty()) {
                nonEmptyArgList.add(nonEmptyArgListContext.get(0));
            }
        }
        List<Object> argumentNames = new ArrayList<>();
        while (!arguments.empty()) {
            Object argNodeId = arguments.pop();
            List<Object> name = g.V().has("nodeId", argNodeId)
                    .outE().has("rule", "expression").inV()
                    .outE().has("rule", "expression").inV()
                    .outE().has("rule", "nonTypeName").inV()
                    .repeat(__.out()).until(__.not(__.out()))
                    .values("value").toList();
            if (!name.isEmpty()) {
                argumentNames.add(name.get(0));
            }
        }
        return argumentNames;
    }

    private void checkControls(GraphTraversalSource g, Map<Object, List<Object>> controls,
            Map<Object, HeaderInfo> globalHeaders, Map<Object, List<Object>> headerTypes,
            Map<Object, Object> nodeIdOfControlNames) {
        System.out.println("---checkControls---");
        for (Object controlNodeId : controls.keySet()) {
            System.out.println("control: " + nodeIdOfControlNames.get(controlNodeId) + ", nodeId: " + controlNodeId);
            section.addEntry(new TitleEntry("Control: " + nodeIdOfControlNames.get(controlNodeId)));
            List<List<Object>> fullHdrNames = getFullHdrNames(controls.get(controlNodeId), globalHeaders);
            List<Path> pathList = g.V().has("nodeId", controlNodeId)
                    .repeat(__.out("cfg"))
                    .until(__.not(__.out("cfg")))
                    .path().by(__.values("nodeId"))
                    .toList();

            Map<Object, List<InstructionEffect>> nodeValueInstruction = new HashMap<>();

            Map<Object, Object> tables = getTablesOfControl(g, controlNodeId);

            Set<Object> printedNodes = new HashSet<>();
            Set<Object> actionsPrintedNodes = new HashSet<>();
            Set<Object> posValueCalculated = new HashSet<>();
            Set<Object> actionsPosValueCalculated = new HashSet<>();
            Map<Object, HeaderInfo> originalGlobalHeaders = headerMapDeepCopy(globalHeaders);
            for (Path p : pathList) {

                Map<Object, HeaderInfo> headers = headerMapDeepCopy(originalGlobalHeaders);

                for (Object nodeId : p.objects()) {
                    if (!nodeValueInstruction.containsKey(nodeId)) {
                        List<InstructionEffect> effects = checkNodeInstruction(g, nodeId, fullHdrNames, tables, headers,
                                controlNodeId, nodeValueInstruction, actionsPrintedNodes, actionsPosValueCalculated);
                        boolean printed = setHeader(headers, effects, printedNodes.contains(nodeId), nodeId, g, null,
                                posValueCalculated);
                        if (printed) {
                            printedNodes.add(nodeId);
                        }
                    } else {
                        List<InstructionEffect> effects = nodeValueInstruction.get(nodeId);
                        boolean printed = setHeader(headers, effects, printedNodes.contains(nodeId), nodeId, g, null,
                                posValueCalculated);
                        if (printed) {
                            printedNodes.add(nodeId);
                        }
                    }
                }

                syncHeadersMap(globalHeaders, headers);
            }

            
            System.out.println("------");
        }
    }

    private boolean setHeader(Map<Object, HeaderInfo> headers, List<InstructionEffect> effectList, boolean printed,
            Object nodeId, GraphTraversalSource g, Object action, Set<Object> posValueCalculatedSet) {
        boolean result = false;
        if (effectList == null) {
            return false;
        }
        String lineString = "";
        List<Object> line = g.V().has("nodeId", nodeId).values("line").toList();
        if (!line.isEmpty()) {
            lineString = " (line: " + line.get(0) + ")";
        }
        String actionString = "";
        if (action != null) {
            actionString = "action: " + action + ":\n  ";
        }
        boolean posValueCalculatedBool = false;
        for (InstructionEffect effect : effectList) {
            if (effect == null || effect.getHeader() == null) {
                return false;
            }
            HeaderInfo headerInfo = headers.get(effect.getHeader().get(1));
            if (effect.getField() == null) {
                if (effect.shouldHaveValue()) {
                    if (HeaderStatus.INVALID.equals(headerInfo.getProgramStatus()) && !printed) {
                        System.out.println(actionString + "WARNING -> " + getHeaderNameStr(effect.getHeader())
                                + " used, but has INVALID status" + lineString);
                        section.addEntry(new ErrorEntry(Severity.WARNING,
                                actionString + getHeaderNameStr(effect.getHeader())
                                        + " used, but has INVALID status",
                                line.get(0)));
                        changeScore(-3);
                        section.addEntry(new ScoreEntry(-3));
                        result = true;
                    } else if (HeaderStatus.VALID.equals(headerInfo.getProgramStatus())
                            && !posValueCalculatedSet.contains(nodeId)) {
                        System.out.println(actionString + "POS -> " + getHeaderNameStr(effect.getHeader())
                                + " used with VALID status" + lineString);
                        changeScore(1);
                        posValueCalculatedBool = true;
                    }

                } else {
                    if (effect.hasValue()) {
                        if (HeaderStatus.VALID.equals(headerInfo.getProgramStatus()) && !printed) {
                            System.out.println(
                                    actionString + "WARNING -> status of " + getHeaderNameStr(effect.getHeader())
                                            + " is set to VALID, but it may already have VALID status" + lineString);
                            section.addEntry(
                                    new ErrorEntry(Severity.WARNING,
                                            actionString + "status of " + getHeaderNameStr(effect.getHeader())
                                                    + " is set to VALID, but it may already have VALID status",
                                            line.get(0)));
                            changeScore(-1);
                            section.addEntry(new ScoreEntry(-1));
                            result = true;
                        }
                        headerInfo.setProgramStatus(HeaderStatus.VALID);
                    } else {
                        headerInfo.setProgramStatus(HeaderStatus.INVALID);
                        headerInfo.getFields().forEach(x -> {
                            x.setHasValue(false);
                        });
                    }
                }
            } else {
                Object fieldName = effect.getField();
                if (effect.shouldHaveValue()) {
                    int i = 0;
                    while (i < headerInfo.getFields().size()
                            && !fieldName.equals(headerInfo.getFields().get(i).getName())) {
                        i++;
                    }
                    if (i < headerInfo.getFields().size()) {
                        
                            if (!headerInfo.getFields().get(i).hasValue() && !printed) {
                                System.out.println(
                                        actionString + "WARNING -> " + fieldName + " has no value" + lineString);
                                section.addEntry(
                                        new ErrorEntry(Severity.WARNING, actionString + fieldName + " has no value",
                                                line.get(0)));
                                changeScore(-2);
                                section.addEntry(new ScoreEntry(-2));
                                result = true;
                            } else if (headerInfo.getFields().get(i).hasValue() && !posValueCalculatedSet.contains(nodeId)) {
                                System.out.println(actionString + "POS -> " + fieldName + " has value" + lineString);
                                changeScore(1);
                                posValueCalculatedBool = true;
                            }

                        
                    } else {
                        if (!"isValid".equals(fieldName) && HeaderStatus.INVALID.equals(headerInfo.getProgramStatus())
                                && !printed) {
                            System.out.println(actionString + "WARNING -> method (" + fieldName + ") call on "
                                    + getHeaderNameStr(effect.getHeader())
                                    + ", but it has INVALID status" + lineString);
                            section.addEntry(
                                    new ErrorEntry(Severity.WARNING,
                                            actionString + "method (" + fieldName + ") call on "
                                                    + getHeaderNameStr(effect.getHeader())
                                                    + ", but it has INVALID status",
                                            line.get(0)));
                            changeScore(-3);
                            section.addEntry(new ScoreEntry(-3));
                            result = true;
                        }
                    }

                } else {
                    headerInfo.getFields().forEach(x -> {
                        if (fieldName.equals(x.getName())) {
                            x.setHasValue(effect.hasValue());
                        }
                    });
                }
            }
        }
        if (posValueCalculatedBool) {
            posValueCalculatedSet.add(nodeId);
        }
        
        return result;
    }

    private List<InstructionEffect> checkNodeInstruction(GraphTraversalSource g, Object nodeToCheck,
            List<List<Object>> fullHdrNames, Map<Object, Object> tables, Map<Object, HeaderInfo> headers,
            Object controlNodeId, Map<Object, List<InstructionEffect>> nodeValueInstruction,
            Set<Object> actionsPrintedNodes, Set<Object> actionsPosValueCalculated) {
        List<Object> nodeClass = g.V().has("nodeId", nodeToCheck).values("class").toList();
        if (nodeClass.isEmpty()) {
            return null;
        }

        if ("AssignmentOrMethodCallStatementContext".equals(nodeClass.get(0))) {
            Object nodeId = nodeToCheck;
            List<InstructionEffect> result = new ArrayList<>();
            for (List<Object> hdr : fullHdrNames) {

                checkExpression(g, nodeId, result, hdr);
                // ertekadas bal oldalan szereples
                List<Map<Object, Object>> leftSide = g.V().has("nodeId", nodeId)
                        .has("class", "AssignmentOrMethodCallStatementContext")
                        .filter(
                                __.out().has("class", "LvalueContext")
                                        .filter(
                                                __.out().has("class", "LvalueContext")
                                                        .filter(
                                                                __.out().has("class", "LvalueContext")
                                                                        .filter(
                                                                                __.out().has("class",
                                                                                        "PrefixedNonTypeNameContext")
                                                                                        .repeat(__.out())
                                                                                        .until(__.not(__.out()))
                                                                                        .has("value", hdr.get(0))))
                                                        .and(
                                                                __.out().has("class", "NameContext")
                                                                        .repeat(__.out()).until(__.not(__.out()))
                                                                        .has("value", hdr.get(1)))))
                        .and(
                                __.out().has("class", "TerminalNodeImpl").has("value", "="))
                        .valueMap("nodeId", "line").toList();

                if (leftSide.size() == 1) { // ha ez 1, akkor ertekadas bal oldala, ha 0 akkor nem
                    Object leftSideNode = ((List<?>) leftSide.get(0).get("nodeId")).get(0);
                    List<Object> fieldName = g.V().has("nodeId", leftSideNode)
                            .outE().has("rule", "lvalue").inV()
                            .outE().has("rule", "name").inV().repeat(__.out()).until(__.not(__.out()))
                            .values("value").toList();
                    if (!fieldName.isEmpty()) {
                        result.add(
                                new InstructionEffect(List.of(hdr.get(0), hdr.get(1)), fieldName.get(0), true, false));
                    }
                }
                List<Map<Object, Object>> methodCallForHdr = g.V().has("nodeId", nodeId)
                        .has("class", "AssignmentOrMethodCallStatementContext")
                        .filter(
                                __.out().has("class", "LvalueContext")
                                        .filter(
                                                __.out().has("class", "LvalueContext")
                                                        .filter(
                                                                __.out().has("class", "LvalueContext")
                                                                        .filter(
                                                                                __.out().has("class",
                                                                                        "PrefixedNonTypeNameContext")
                                                                                        .repeat(__.out())
                                                                                        .until(__.not(__.out()))
                                                                                        .has("value", hdr.get(0))))
                                                        .and(
                                                                __.out().has("class", "NameContext")
                                                                        .repeat(__.out()).until(__.not(__.out()))
                                                                        .has("value", hdr.get(1)))))
                        .and(
                                __.outE().has("rule", "argumentList"))
                        .valueMap("nodeId", "line").toList();
                if (methodCallForHdr.size() == 1) { // ha ez 1, akkor metodushivas, ha 0 akkor nem
                    Object methodNode = ((List<?>) methodCallForHdr.get(0).get("nodeId")).get(0);
                    List<Object> methodNameList = g.V().has("nodeId", methodNode)
                            .outE().has("rule", "lvalue").inV()
                            .outE().has("rule", "name").inV().repeat(__.out()).until(__.not(__.out()))
                            .values("value").toList();
                    if (!methodNameList.isEmpty()) {
                        Object methodName = methodNameList.get(0);
                        if ("setValid".equals(methodName)) {
                            result.add(new InstructionEffect(List.of(hdr.get(0), hdr.get(1)), null, true, false));
                        } else if ("setInvalid".equals(methodName)) {
                            result.add(new InstructionEffect(List.of(hdr.get(0), hdr.get(1)), null, false, false));
                        } else {
                            result.add(new InstructionEffect(List.of(hdr.get(0), hdr.get(1)), null, false, true));
                        }
                    }
                }

            }
            nodeValueInstruction.put(nodeToCheck, result);
            return result;
        } else if ("ConditionalStatementContext".equals(nodeClass.get(0))) {
            List<Object> nodeIdList = g.V().has("nodeId", nodeToCheck).outE().has("rule", "expression").inV()
                    .values("nodeId")
                    .toList();
            if (!nodeIdList.isEmpty()) {
                Object nodeId = nodeIdList.get(0);
                List<InstructionEffect> result = new ArrayList<>();
                for (List<Object> hdr : fullHdrNames) {
                    checkExpression(g, nodeId, result, hdr);
                }
                nodeValueInstruction.put(nodeToCheck, result);
                return result;
            }
        } else if ("DirectApplicationContext".equals(nodeClass.get(0))) {
            checkMethodCallForTable(g, nodeToCheck, fullHdrNames, tables, headers, controlNodeId, actionsPrintedNodes,
                    actionsPosValueCalculated);
        } else {
            nodeValueInstruction.put(nodeToCheck, null);
        }

        return null;
    }

    private List<InstructionEffect> checkMethodCallForTable(GraphTraversalSource g, Object nodeId,
            List<List<Object>> fullHdrNames, Map<Object, Object> tables, Map<Object, HeaderInfo> headers,
            Object controlNodeId, Set<Object> actionsPrintedNodes, Set<Object> actionsPosValueCalculated) {
        List<Object> tableApplication = g.V().has("nodeId", nodeId)
                .filter(
                        __.outE().has("rule", "typeName"))
                .and(
                        __.outE().has("rule", "APPLY").inV().has("value", "apply"))
                .outE().has("rule", "typeName").inV()
                .repeat(__.out()).until(__.not(__.out()))
                .values("value").toList();
        if (!tableApplication.isEmpty() && tables.containsKey(tableApplication.get(0))) {
            checkTableAction(g, fullHdrNames, tables.get(tableApplication.get(0)), headers, controlNodeId, tables,
                    actionsPrintedNodes, actionsPosValueCalculated);
        }
        return new ArrayList<>();
    }

    private void checkTableAction(GraphTraversalSource g, List<List<Object>> fullHdrNames,
            Object tableNodeId, Map<Object, HeaderInfo> globalHeaders, Object controlNodeId,
            Map<Object, Object> tables, Set<Object> actionsPrintedNodes, Set<Object> actionsPosValueCalculated) {
        List<Object> actions = g.V().has("nodeId", tableNodeId)
                .outE().has("rule", "tablePropertyList").inV()
                .repeat(__.out("syn")).emit()
                .has("class", "TablePropertyContext")
                .filter(
                        __.outE().has("rule", "ACTIONS"))
                .outE().has("rule", "actionList").inV()
                .repeat(__.out("syn")).emit()
                .has("class", "ActionRefContext")
                .outE().has("rule", "name").inV()
                .repeat(__.out()).until(__.not(__.out()))
                .values("value").toList();

        for (Object action : actions) {
            List<Object> actionDecl = g.V().has("nodeId", controlNodeId)
                    .outE().has("rule", "controlLocalDeclarations").inV()
                    .repeat(__.out("syn")).emit()
                    .has("class", "ActionDeclarationContext")
                    .filter(
                            __.outE().has("rule", "name").inV()
                                    .repeat(__.out()).until(__.not(__.out()))
                                    .has("value", action))
                    .values("nodeId").toList();
            if (!actionDecl.isEmpty()) {
                Object actionDeclNode = actionDecl.get(0);
                List<Path> pathList = g.V().has("nodeId", actionDeclNode)
                        .repeat(__.out("cfg"))
                        .until(__.not(__.out("cfg")))
                        .path().by(__.values("nodeId"))
                        .toList();

                Map<Object, List<InstructionEffect>> nodeValueInstruction = new HashMap<>();
                Map<Object, HeaderInfo> originalGrobalHeaders = headerMapDeepCopy(globalHeaders);
                for (Path p : pathList) {

                    Map<Object, HeaderInfo> headers = headerMapDeepCopy(originalGrobalHeaders);

                    for (Object nodeId : p.objects()) {
                        if (!nodeValueInstruction.containsKey(nodeId)) {
                            List<InstructionEffect> effects = checkNodeInstruction(g, nodeId, fullHdrNames, tables,
                                    headers,
                                    controlNodeId, nodeValueInstruction, actionsPrintedNodes,
                                    actionsPosValueCalculated);
                            boolean printed = setHeader(headers, effects,
                                    actionsPrintedNodes.contains(nodeId), nodeId, g,
                                    action, actionsPosValueCalculated);
                            if (printed) {
                                actionsPrintedNodes.add(nodeId);
                            }
                        } else {
                            List<InstructionEffect> effects = nodeValueInstruction.get(nodeId);
                            boolean printed = setHeader(headers, effects,
                                    actionsPrintedNodes.contains(nodeId), nodeId, g,
                                    action, actionsPosValueCalculated);
                            if (printed) {
                                actionsPrintedNodes.add(nodeId);
                            }
                        }
                    }

                    syncHeadersMap(globalHeaders, headers);
                }
            }

        }

    }

    private Map<Object, Object> getTablesOfControl(GraphTraversalSource g, Object controlNodeId) {
        Map<Object, Object> result = new HashMap<>();
        List<Object> tableDeclList = g.V().has("nodeId", controlNodeId)
                .outE().has("rule", "controlLocalDeclarations").inV()
                .repeat(__.out("syn")).emit()
                .has("class", "ControlLocalDeclarationContext")
                .outE().has("rule", "tableDeclaration").inV()
                .values("nodeId").toList();
        for (Object tableDecl : tableDeclList) {
            List<Object> name = g.V().has("nodeId", tableDecl)
                    .outE().has("rule", "name").inV()
                    .repeat(__.out()).until(__.not(__.out()))
                    .values("value").toList();
            if (!name.isEmpty()) {
                result.put(name.get(0), tableDecl);
            }
        }
        return result;
    }

    private void checkExpression(GraphTraversalSource g, Object nodeId, List<InstructionEffect> result,
            List<Object> hdr) {
        // jobb oldali kifejezesben szereples
        List<Map<Object, Object>> expression = g.V().has("nodeId", nodeId).repeat(__.out("syn")).emit()
                .has("class", "ExpressionContext")
                .filter(
                        __.out().has("class", "ExpressionContext")
                                .filter(
                                        __.out().has("class", "ExpressionContext")
                                                .repeat(__.out()).until(__.not(__.out())).has("value", hdr.get(0)))
                                .and(
                                        __.out().has("class", "NameContext")
                                                .repeat(__.out()).until(__.not(__.out())).has("value", hdr.get(1))))
                .valueMap("nodeId", "line").toList();
        
        if (!expression.isEmpty()) {
            for (Map<Object, Object> expr : expression) {
                Object expressionNode = ((List<?>) expr.get("nodeId")).get(0);
                List<Object> fieldName = g.V().has("nodeId", expressionNode)
                        .outE().has("rule", "name").inV().repeat(__.out()).until(__.not(__.out()))
                        .values("value").toList();
                if (!fieldName.isEmpty()) {
                    result.add(new InstructionEffect(List.of(hdr.get(0), hdr.get(1)), fieldName.get(0), false, true));
                }
            }
        }
    }

    private List<List<Object>> getFullHdrNames(List<Object> paramNames, Map<Object, HeaderInfo> headers) {
        List<List<Object>> result = new ArrayList<>();
        for (Object paramName : paramNames) {
            for (Object hdrName : headers.keySet()) {
                result.add(List.of(paramName, hdrName, headers.get(hdrName).getFields()));
            }
        }
        return result;
    }

    private String getTypeOfParameter(GraphTraversalSource g, Object paramNodeId) {
        List<Object> paramType = g.V().has("nodeId", paramNodeId)
                .outE().has("rule", "typeRef").inV()
                .outE().has("rule", "typeName").inV()
                .repeat(__.out()).until(__.not(__.out())).values("value")
                .toList();
        if (paramType.isEmpty()) {
            return null;
        }
        return paramType.get(0).toString();
    }

    private Object getNameOfParameter(GraphTraversalSource g, Object paramNodeId) {
        List<Object> paramName = g.V().has("nodeId", paramNodeId)
                .outE().has("rule", "name").inV()
                .outE().has("rule", "nonTypeName").inV()
                .repeat(__.out()).until(__.not(__.out())).values("value")
                .toList();
        if (paramName.isEmpty()) {
            return null;
        }
        return paramName.get(0);
    }

    private List<Object> getHdrToSet(GraphTraversal<Vertex, Vertex> g, String methodName) {
        GraphTraversal<Vertex, Vertex> assignmentOrMethodCallStatementContext = g.filter(
                __.has("class", "AssignmentOrMethodCallStatementContext"));
        List<Object> methodCalls = assignmentOrMethodCallStatementContext.filter(
                __.out().has("class", "LvalueContext").filter(
                        __.out().has("class", "NameContext")
                                .repeat(__.out()).until(__.not(__.out())).filter(
                                        __.has("class", "TerminalNodeImpl"))
                                .and(
                                        __.has("value", methodName))))
                .values("nodeId").toList();

        return methodCalls;
    }

    private List<String> getHdrName(GraphTraversalSource g, Object nodeId) {
        List<Map<Object, Object>> nodes = g.V().has("nodeId", nodeId)
                .repeat(
                        __.outE("syn")
                                .inV())
                .until(__.not(__.out())).filter(
                        __.has("class", "TerminalNodeImpl"))
                .and(
                        __.inE().has("rule", "IDENTIFIER"))
                .valueMap("nodeId", "value").toList();

        List<String> list = new ArrayList<>();
        nodes.sort(Comparator.comparing(
                m -> (Long) ((List<?>) m.get("nodeId")).get(0)));
        nodes.forEach(x -> list.add(x.get("value").toString()));
        return list;
    }

    private Map<Object, List<Object>> getHeaderTypes(GraphTraversalSource g) {
        Map<Object, List<Object>> headerFields = new HashMap<>();

        List<Object> headerTypeDeclarations = g.V().has("class", "TypeDeclarationContext")
                .out().has("class", "DerivedTypeDeclarationContext")
                .out().has("class", "HeaderTypeDeclarationContext")
                .values("nodeId").toList();
        for (Object decl : headerTypeDeclarations) {
            List<Object> headerName = g.V().has("nodeId", decl)
                    .out().has("class", "NameContext")
                    .repeat(__.out()).until(__.not(__.out())).values("value").toList();

            List<Object> headerFieldsNames = g.V().has("nodeId", decl)
                    .out().has("class", "StructFieldListContext")
                    .repeat(
                            __.outE("syn")
                                    .inV())
                    .emit().dedup().has("class", "NameContext")
                    .repeat(__.out()).until(__.not(__.out()))
                    .values("value").toList();
            if (!headerName.isEmpty()) {
                headerFields.put(headerName.get(0), headerFieldsNames);
            }
        }

        return headerFields;
    }

    private Map<Object, HeaderInfo> getHeaders(GraphTraversalSource g, Map<Object, List<Object>> headerTypes) {
        Map<Object, HeaderInfo> headers = new HashMap<>();
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
                List<HeaderFieldInfo> fieldList = headerTypes.get(type.get(0)).stream()
                        .map(x -> new HeaderFieldInfo(x, false))
                        .toList();
                headers.put(name.get(0), new HeaderInfo(fieldList, HeaderStatus.INVALID));
            }
        }
        return headers;
    }

    private void checkParse(GraphTraversalSource g, Map<Object, HeaderInfo> headers) {
        List<Object> methodCalls = g.V().has("class", "ParserDeclarationContext").repeat(
                __.outE("syn")
                        .inV())
                .emit().dedup().has("class", "AssignmentOrMethodCallStatementContext")
                .values("nodeId").toList();

        // packet_in parameter neve
        List<Object> packetInParam = g.V().has("class", "ParserDeclarationContext")
                .outE().has("rule", "parserTypeDeclaration").inV()
                .outE().has("rule", "parameterList").inV()
                .repeat(__.outE("syn").inV())
                .emit().dedup().has("class", "ParameterContext").filter(
                        __.outE().has("rule", "typeRef").inV()
                                .outE().has("rule", "typeName").inV()
                                .repeat(__.out()).until(__.not(__.out())).has("value", "packet_in"))
                .outE().has("rule", "name").inV()
                .repeat(__.out()).until(__.not(__.out()))
                .values("value").toList();

        if (packetInParam.isEmpty()) {
            System.out.println("packet_in parameter not found in parser block.");
        }
        Object packetInParamName = packetInParam.get(0);

        for (Object methodCall : methodCalls) {
            List<Object> methodName = g.V().has("nodeId", methodCall)
                    .outE().has("rule", "lvalue").inV()
                    .outE().has("rule", "name").inV()
                    .repeat(__.out()).until(__.not(__.out()))
                    .values("value").toList();
            List<Object> methodCallOn = g.V().has("nodeId", methodCall)
                    .outE().has("rule", "lvalue").inV()
                    .outE().has("rule", "lvalue").inV()
                    .repeat(__.out()).until(__.not(__.out()))
                    .values("value").toList();

            if (!methodName.isEmpty() && methodName.get(0).equals("extract") && !methodCallOn.isEmpty()
                    && methodCallOn.get(0).equals(packetInParamName)) {
                List<Map<Object, Object>> hdrNameNodes = g.V().has("nodeId", methodCall)
                        .outE().has("rule", "argumentList").inV()
                        .outE().has("rule", "nonEmptyArgList").inV()
                        .outE().has("rule", "argument").inV()
                        .outE().has("rule", "expression").inV()
                        .repeat(
                                __.outE("syn")
                                        .inV())
                        .until(__.not(__.out()))
                        .filter(
                                __.has("class", "TerminalNodeImpl"))
                        .and(
                                __.inE().has("rule", "IDENTIFIER"))
                        .valueMap("nodeId", "value").toList();

                List<String> list = new ArrayList<>();
                hdrNameNodes.sort(Comparator.comparing(
                        m -> (Long) ((List<?>) m.get("nodeId")).get(0)));
                hdrNameNodes.forEach(x -> list.add(x.get("value").toString()));

                if (!list.isEmpty()) {
                    String name = stripBracket(list.get(list.size() - 1));

                    HeaderInfo info = headers.get(name);
                    info.setProgramStatus(HeaderStatus.VALID);
                    info.getFields().forEach(x -> x.setHasValue(true));
                }
            }
        }
    }

    private void checkDeparse(GraphTraversalSource g, Map<Object, HeaderInfo> headers) {
        System.out.println("----deparse-----");
        section.addEntry(new TitleEntry("Deparser block:"));
        List<Object> deparserControl = g.V().has("class", "ControlDeclarationContext").filter(
                __.outE().has("rule", "controlTypeDeclaration").inV()
                        .outE().has("rule", "parameterList").inV()
                        .repeat(__.outE("syn").inV())
                        .emit().dedup().has("class", "ParameterContext")
                        .outE().has("rule", "typeRef").inV()
                        .outE().has("rule", "typeName").inV()
                        .repeat(__.out()).until(__.not(__.out())).has("value", "packet_out"))
                .values("nodeId").toList();

        if (deparserControl.isEmpty()) {
            System.out.println("Deparser block not found.");
            return;
        }
        Object deparserControlNodeId = deparserControl.get(0);

        // packet_out parameter neve
        List<Object> packetOutParam = g.V().has("nodeId", deparserControlNodeId)
                .outE().has("rule", "controlTypeDeclaration").inV()
                .outE().has("rule", "parameterList").inV()
                .repeat(__.outE("syn").inV())
                .emit().dedup().has("class", "ParameterContext").filter(
                        __.outE().has("rule", "typeRef").inV()
                                .outE().has("rule", "typeName").inV()
                                .repeat(__.out()).until(__.not(__.out())).has("value", "packet_out"))
                .outE().has("rule", "name").inV()
                .repeat(__.out()).until(__.not(__.out()))
                .values("value").toList();

        if (packetOutParam.isEmpty()) {
            System.out.println("packet_out parameter not found in deparser block.");
        }
        Object packetOutParamName = packetOutParam.get(0);

        List<Object> methodCalls = g.V().has("nodeId", deparserControlNodeId).repeat(__.outE("syn").inV())
                .emit().dedup().has("class", "AssignmentOrMethodCallStatementContext").filter(
                        __.outE().has("rule", "argumentList"))
                .values("nodeId").toList();
        for (Object methodCall : methodCalls) {
            List<Object> methodName = g.V().has("nodeId", methodCall)
                    .outE().has("rule", "lvalue").inV()
                    .outE().has("rule", "name").inV()
                    .repeat(__.out()).until(__.not(__.out()))
                    .values("value").toList();
            List<Object> methodCallOn = g.V().has("nodeId", methodCall)
                    .outE().has("rule", "lvalue").inV()
                    .outE().has("rule", "lvalue").inV()
                    .repeat(__.out()).until(__.not(__.out()))
                    .values("value").toList();

            if (!methodName.isEmpty() && methodName.get(0).equals("emit") && !methodCallOn.isEmpty()
                    && methodCallOn.get(0).equals(packetOutParamName)) {
                List<Map<Object, Object>> hdrNameNodes = g.V().has("nodeId", methodCall)
                        .outE().has("rule", "argumentList").inV()
                        .outE().has("rule", "nonEmptyArgList").inV()
                        .outE().has("rule", "argument").inV()
                        .outE().has("rule", "expression").inV()
                        .repeat(
                                __.outE("syn")
                                        .inV())
                        .until(__.not(__.out()))
                        .filter(
                                __.has("class", "TerminalNodeImpl"))
                        .and(
                                __.inE().has("rule", "IDENTIFIER"))
                        .valueMap("nodeId", "value").toList();

                List<String> list = new ArrayList<>();
                hdrNameNodes.sort(Comparator.comparing(
                        m -> (Long) ((List<?>) m.get("nodeId")).get(0)));
                hdrNameNodes.forEach(x -> list.add(x.get("value").toString()));
                if (!list.isEmpty()) {
                    String name = stripBracket(list.get(list.size() - 1));
                    int headerScore = 0;
                    System.out.println("emit: " + name);
                    section.addEntry(new Entry(Severity.INFO, "emit: " + name));
                    if (headers.get(name) != null) {
                        System.out.println("  status: " + headers.get(name).getProgramStatus());
                        section.addEntry(
                                new Entry(Severity.INFO, "&nbsp; status: " + headers.get(name).getProgramStatus()));
                        if (HeaderStatus.INVALID.equals(headers.get(name).getProgramStatus())) {
                            headerScore -= 1;
                        }
                        List<HeaderFieldInfo> noValueFields = headers.get(name).getFields().stream()
                                .filter(x -> !x.hasValue())
                                .toList();
                        System.out.println("  no value fields: " + noValueFields.stream().map(x -> x.getName()).toList());
                        section.addEntry(new Entry(Severity.INFO,
                                "&nbsp; no value fields: " + noValueFields.stream().map(x -> x.getName()).toList()));
                        headerScore += 0 - noValueFields.size();

                        System.out.println("  explicitly specified header name");
                        section.addEntry(new Entry(Severity.INFO, "&nbsp; explicitly specified header name"));
                        headerScore += 1;

                        changeScore(headerScore);
                        section.addEntry(new ScoreEntry(headerScore));
                    } else {
                        System.out.println("The parameter of emit method is not an explicitly specified header name.");
                        section.addEntry(new Entry(Severity.WARNING,
                                "&nbsp; The parameter of emit method is not an explicitly specified header name."));
                    }
                }
            }
        }
        System.out.println("------");
    }

    private String stripBracket(String str) {
        if (str != null) {
            if (str.startsWith("[")) {
                str = str.substring(1);
            }
            if (str.endsWith("]")) {
                str = str.substring(0, str.length() - 1);
            }
        }
        return str;
    }

    private Map<Object, HeaderInfo> headerMapDeepCopy(Map<Object, HeaderInfo> original) {
        Map<Object, HeaderInfo> copy = new HashMap<>();
        for (Object key : original.keySet()) {
            copy.put(key, new HeaderInfo(original.get(key)));
        }
        return copy;
    }

    private void syncHeadersMap(Map<Object, HeaderInfo> globalHeaders, Map<Object, HeaderInfo> headers) {
        for (Object key : globalHeaders.keySet()) {
            HeaderInfo globalHeaderInfo = globalHeaders.get(key);
            HeaderInfo localHeaderInfo = headers.get(key);
            if (HeaderStatus.INVALID.equals(localHeaderInfo.getProgramStatus())) {
                globalHeaderInfo.setProgramStatus(HeaderStatus.INVALID);
            }
            for (int i = 0; i < globalHeaderInfo.getFields().size(); i++) {
                boolean globalField = globalHeaderInfo.getFields().get(i).hasValue();
                boolean localField = localHeaderInfo.getFields().get(i).hasValue();
                globalHeaderInfo.getFields().get(i).setHasValue(globalField && localField);
            }

        }
    }

    private String getHeaderNameStr(List<Object> hdr) {
        StringJoiner joiner = new StringJoiner(".");
        hdr.forEach(item -> joiner.add(item.toString()));
        return joiner.toString();
    }
}
