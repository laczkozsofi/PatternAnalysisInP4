package p4query.experts.patternanalysis;

public class HeaderFieldInfo {
    
    private Object name;
    private boolean hasValue;

    public HeaderFieldInfo(){}

    public HeaderFieldInfo(Object name, boolean hasValue) {
        this.name = name;
        this.hasValue = hasValue;
    }

    public HeaderFieldInfo(HeaderFieldInfo headerFieldInfo) {
        this.name = headerFieldInfo.name;
        this.hasValue = headerFieldInfo.hasValue;
    }

    public Object getName() {
        return name;
    }

    public void setName(Object name) {
        this.name = name;
    }

    public boolean hasValue() {
        return hasValue;
    }

    public void setHasValue(boolean hasValue) {
        this.hasValue = hasValue;
    }

    @Override
    public String toString(){
        return "{ name: " + name.toString() + ", hasValue: " + hasValue + "}";
    }


}
