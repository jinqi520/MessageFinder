package burp;

import java.net.URL;

public class JsonpIssue implements IScanIssue{
    private IHttpService httpService;
    private URL url;
    private IHttpRequestResponse[] httpMessages;
    private String name;
    private String detail;
    private String severity;

    public JsonpIssue(IHttpService httpService, URL url, IHttpRequestResponse[] httpMessages, String name, String detail, String severity){
        this.httpService = httpService;
        this.url = url;
        this.httpMessages = httpMessages;
        this.name = name;
        this.detail = detail;
        this.severity = severity;
    }

    public URL getUrl() {
        return url;
    }

    public String getIssueName() {
        return name;
    }

    public int getIssueType() {
        return 0;
    }

    public String getSeverity() {
        return severity;
    }

    public String getConfidence() {
        return "Certain";
    }

    public String getIssueBackground() {
        return null;
    }

    public String getRemediationBackground() {
        return null;
    }

    public String getIssueDetail() {
        return detail;
    }

    public String getRemediationDetail() {
        return null;
    }

    public IHttpRequestResponse[] getHttpMessages() {
        return httpMessages;
    }

    public IHttpService getHttpService() {
        return httpService;
    }

}
