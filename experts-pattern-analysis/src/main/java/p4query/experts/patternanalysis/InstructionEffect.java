package p4query.experts.patternanalysis;

import java.util.List;

public class InstructionEffect {
    private List<Object> header;
    private Object field;
    private boolean hasValue;
    private boolean shouldHaveValue;

    public InstructionEffect(){}

    public InstructionEffect(List<Object> header, Object field, boolean hasValue, boolean shouldHaveValue) {
        this.header = header;
        this.field = field;
        this.hasValue = hasValue;
        this.shouldHaveValue = shouldHaveValue;
    }

    public List<Object> getHeader() {
        return header;
    }

    public void setHeader(List<Object> header) {
        this.header = header;
        this.field = null;
    }

    public Object getField() {
        return field;
    }

    public void setField(Object field) {
        this.header = null;
        this.field = field;
    }

    public boolean hasValue() {
        return hasValue;
    }

    public void setHasValue(boolean hasValue) {
        this.hasValue = hasValue;
    }

    public boolean shouldHaveValue() {
        return shouldHaveValue;
    }

    public void setShouldHaveValue(boolean shouldHaveValue) {
        this.shouldHaveValue = shouldHaveValue;
    }

    @Override
    public String toString(){
        return "{ header: " + header + ", field: " + field + ", hasValue: " + hasValue + ", shouldHave: " + shouldHaveValue + "}";
    }
}
