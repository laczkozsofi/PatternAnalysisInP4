package p4query.experts.patternanalysis.report.entries;

import p4query.experts.patternanalysis.report.Severity;

public class ScoreEntry extends Entry {
    
    private int score;

    public ScoreEntry(String message, int score) {
        super(Severity.INFO, message);
        this.score = score;
    }

    public ScoreEntry(int score) {
        super(Severity.INFO, "Score:");
        this.score = score;
    }

    public int getScore() {
        return this.score;
    }

    public void setScore(int score) {
        this.score = score;
    }

    @Override
    public String toString() {
        return getMessage() + " " + score + "\n";
    }
}
