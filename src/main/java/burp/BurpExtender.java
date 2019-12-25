package burp;

import java.io.*;
import java.net.URL;
import java.nio.Buffer;
import java.util.ArrayList;
import java.util.List;

public class BurpExtender  implements IBurpExtender, IScannerCheck{
    public IBurpExtenderCallbacks callbacks;
    public List<String> KEYWORDS = new ArrayList<String>();
    public PrintWriter sout;
    public IExtensionHelpers helps;
    public String FILENAME = "secret-keywords.txt";

    public void getKeyWord(){
        InputStream inputStream = BurpExtender.class.getResourceAsStream("/secret-keywords.txt");
        try{
            InputStreamReader inputStreamReader = new InputStreamReader(inputStream, "UTF-8");
            BufferedReader reader = new BufferedReader(inputStreamReader);
            String keyword = reader.readLine();
            while(keyword!=null){
                KEYWORDS.add(keyword);
                keyword = reader.readLine();
            }
        }catch (Exception e){
            e.printStackTrace();
        }
    }


    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.sout = new PrintWriter(callbacks.getStdout(),true);
        this.helps = callbacks.getHelpers();
        sout.println("start message find!");
        getKeyWord();
        callbacks.setExtensionName("Message Finder");
        callbacks.registerScannerCheck(this);

    }

    // IHttpRequestResponseWithMarkers 是IHttpRequestResponse的子类，用于扩展IHttpRequestResponse来突出显示一些字段，例如扫描器的payload插入点，高亮显示扫描发现的问题
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        List<IScanIssue> issues = new ArrayList<IScanIssue>();
        List<int[]> matches;
        for(String keyword : KEYWORDS){
            matches = keywordMatch(baseRequestResponse.getResponse(), helps.stringToBytes(keyword));
            if(matches.size() > 0){
                sout.println(keyword);
                issues.add(
                        new MessageFindIssue(
                                baseRequestResponse.getHttpService(),
                                helps.analyzeRequest(baseRequestResponse).getUrl(),
                                new IHttpRequestResponse[]{callbacks.applyMarkers(baseRequestResponse, null, matches)},
                                "Key Word find!",
                                "The response contains the string: " + keyword,
                                "High"
                        )
                );
            }
        }

        return issues;
    }

    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return null;
    }

    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        // 之所以要注释掉下面这句话是因为返回包中可能同时存在多个敏感词，由于issuename相同而不会重复爆了，这样可能会有所遗漏
        /*if(existingIssue.getIssueName().equals(newIssue.getIssueName())){
            return -1;
        }*/
        return 0;
    }


    public List<int[]> keywordMatch(byte[] response, byte[] match){
        List<int[]> matchs = new ArrayList<int[]>();
        int start =0;
        while(start < response.length){
            start = helps.indexOf(response, match, false, start, response.length);
            if (start == -1){
                break;
            }
            matchs.add(new int[]{start,start+match.length});
            start = start + match.length;
        }
        return matchs;
    }

    class MessageFindIssue implements IScanIssue{
        private IHttpService httpService;
        private URL url;
        private IHttpRequestResponse[] httpMessages;
        private String name;
        private String detail;
        private String severity;

        public MessageFindIssue(IHttpService httpService, URL url, IHttpRequestResponse[] httpMessages, String name, String detail, String severity){
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