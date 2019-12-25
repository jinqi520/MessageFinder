package burp;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;

public class BurpExtender  implements IBurpExtender, IScannerCheck{
    public IBurpExtenderCallbacks callbacks;


    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;


    }

    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        return null;
    }

    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return null;
    }

    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        if(existingIssue.getIssueName().equals(newIssue.getIssueName())){
            return -1;
        }
        return 0;
    }


    public List<int[]> keywordMatch(byte[] response){
        List<int[]> matchs = new ArrayList<int[]>();

        return matchs;
    }

    class MessageFind implements IScanIssue{
        private IHttpService httpService;
        private URL url;
        private IHttpRequestResponse[] httpMessages;
        private String name;
        private String detail;
        private String severity;

        public MessageFind(IHttpService httpService, URL url, IHttpRequestResponse[] httpMessages, String name, String detail, String severity){
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
}