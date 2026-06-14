package p4query.experts.patternanalysis.report;

import p4query.experts.patternanalysis.report.entries.Entry;

public class HtmlGenerator {
    public String generate(Report report) {
        StringBuilder sb = new StringBuilder();
        // A style rész ChatGPT által generált kód alapján készült.
        sb.append("""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <title>Report</title>
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        margin: 40px;
                        background: #f7f7f7;
                    }
                    h1 {
                        border-bottom: 2px solid #333;
                        padding-bottom: 10px;
                    }
                    h2 {
                        margin-top: 0px;
                    }
                    .section {
                        margin-top: 30px;
                        background: white;
                        padding: 20px;
                        border-radius: 8px;
                        box-shadow: 0 1px 3px rgba(0,0,0,0.1);
                    }
                    
                </style>
            </head>""");
        sb.append("<body><h1>" + report.getTitle() + "</h1>");

        for (Section section : report.getSections()) {
            sb.append("<div class='section'>");
            sb.append("\n<h2>").append(section.getTitle()).append("</h2>\n");

            for (Entry entry : section.getEntries()) {
                sb.append("<p>\n" + entry.toString() + "</p>\n");
            }

            sb.append("</div>");
        }

        sb.append("""
            </body>
            </html>
        """);

        return sb.toString();
    }
}
