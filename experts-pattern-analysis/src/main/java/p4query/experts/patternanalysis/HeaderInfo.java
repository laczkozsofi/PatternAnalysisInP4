package p4query.experts.patternanalysis;

import java.util.ArrayList;
import java.util.List;

public class HeaderInfo {
    
    private List<HeaderFieldInfo> fields;
    private HeaderStatus programStatus;

    public HeaderInfo(){}

    public HeaderInfo(List<HeaderFieldInfo> fields, HeaderStatus programStatus) {
        this.fields = fields;
        this.programStatus = programStatus;
    }

    public HeaderInfo(HeaderInfo headerInfo) {
        this.programStatus = headerInfo.programStatus;
        this.fields = new ArrayList<>();
        headerInfo.fields.forEach(x -> this.fields.add(new HeaderFieldInfo(x)));
    }

    public List<HeaderFieldInfo> getFields() {
        return fields;
    }

    public List<Object> getFieldsNames() {
        return fields.stream().map(x -> x.getName()).toList();
    }

    public void setFields(List<HeaderFieldInfo> fields) {
        this.fields = fields;
    }

    public HeaderStatus getProgramStatus() {
        return programStatus;
    }

    public void setProgramStatus(HeaderStatus programStatus) {
        this.programStatus = programStatus;
    }

    @Override
    public String toString(){
        return "{ progSt: " + programStatus + ", fields: " + fields.toString() + "}";
    }

}
