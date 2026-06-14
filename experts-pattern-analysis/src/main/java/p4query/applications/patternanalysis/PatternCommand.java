package p4query.applications.patternanalysis;

import com.beust.jcommander.Parameter;

import p4query.ontology.providers.AppUI;

public class PatternCommand extends AppUI {
    @Override
    public String getCommandName() { return "patternanalysis"; }

    @Override
    public String[] getCommandNameAliases() {
        return new String[]{};
    }
    
    @Parameter(names = {"-HF", "--headersfile"}, description = "Location of the file which contains the known headers file (relative path)", validateWith = OptionCannotBeValueValidator.class)
    public String headersFile;

    @Parameter(names = {"-HS", "--headerstructname"}, description = "Name of struct of headers in P4 file", validateWith = OptionCannotBeValueValidator.class)
    public String headersStruct;

    @Override
    public String toString() {
        return "PatternCommand [super= " + super.toString()+ ", headersFile=" + headersFile + ", headersStruct=" + headersStruct + "]";
    }

}