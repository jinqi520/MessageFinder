package burp;

import com.sun.org.apache.bcel.internal.generic.GETFIELD;

import java.io.*;
import java.lang.reflect.Array;
import java.net.URL;
import java.nio.Buffer;
import java.util.*;

public class BurpExtender  implements IBurpExtender, IScannerCheck{
    public IBurpExtenderCallbacks callbacks;
    public List<String> KEYWORDS = new ArrayList<String>();
    public PrintWriter sout;
    public IExtensionHelpers helps;
    public String FILENAME = "/secret-keywords.txt";
    public static List<String> jsonps = new ArrayList<String>(Arrays.asList("jsonp","callback","cb","_cb_","_cb","jp","json","r","call","jsonpcallback","jsonpcb","jsb","usercallback"));

    public void getKeyWord(){
        InputStream inputStream = BurpExtender.class.getResourceAsStream(FILENAME);
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
    // callbacks.applyMarkers返回一个IHttpRequestResponseWithMarkers
    // IHttpRequestResponseWithMarkers 是IHttpRequestResponse的子类，用于扩展IHttpRequestResponse来突出显示一些字段，例如扫描器的payload插入点，高亮显示扫描发现的问题
    // 决定将其改成被动扫描，支持1.敏感信息挖掘 2.jsonp劫持 3.xssi
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        List<IScanIssue> issues = new ArrayList<IScanIssue>();
        IHttpService httpService = baseRequestResponse.getHttpService();
        IRequestInfo requestinfo = helps.analyzeRequest(baseRequestResponse);
        String url = requestinfo.getUrl().toString();
        url = url.indexOf("?") > 0 ? url.substring(0,url.indexOf("?")) : url;
        if(Util.isMathch(Config.SUFFIX_REGX, url)){
            return issues;
        }
        if(url.endsWith(".js")){
            issues = check_xssi(issues,baseRequestResponse);
        }else{
            issues = find_message(issues,baseRequestResponse);
        }

        //jsonp劫持只能是get请求
        if(helps.analyzeRequest(baseRequestResponse.getRequest()).getMethod().equals("GET")){
            issues = check_jsonp(issues, baseRequestResponse);
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


    public List<int[]> keywordMatch(byte[] response, byte[] match, int offset){
        List<int[]> matchs = new ArrayList<int[]>();
        int start =0;
        while(start < response.length){
            start = helps.indexOf(response, match, false, start, response.length);
            if (start == -1){
                break;
            }
            matchs.add(new int[]{start + offset,start+match.length + offset});
            start = start + match.length;
        }
        return matchs;
    }

    private List<IScanIssue> find_message(List<IScanIssue> issues,IHttpRequestResponse baseRequestResponse){
        byte[] response;
        List<int[]> matches;
        // 这里只取response包中的body部分
        response = baseRequestResponse.getResponse();
        int start = helps.analyzeResponse(baseRequestResponse.getResponse()).getBodyOffset();
        byte[] body = new byte[response.length - start];
        System.arraycopy(response, start, body, 0, response.length - start);
        for(String keyword : KEYWORDS){
            matches = keywordMatch(body, helps.stringToBytes(keyword), start);
            if(matches.size() > 0){
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

    private List<IScanIssue> check_xssi(List<IScanIssue> issues,IHttpRequestResponse baseRequestResponse){
        byte[] origin_response = baseRequestResponse.getResponse();
        byte[] request =helps.buildHttpRequest(helps.analyzeRequest(baseRequestResponse).getUrl());
        IHttpRequestResponse modife_response = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), request);
        sout.println(modife_response.getRequest().toString());
        // 获取原始返回体
        int start = helps.analyzeResponse(origin_response).getBodyOffset();
        byte[] body = new byte[origin_response.length - start];
        System.arraycopy(origin_response, start, body, 0, origin_response.length - start);
        // 获取修改后的请求包返回体
        byte[] m_response = modife_response.getResponse();
        int m_start = helps.analyzeResponse(m_response).getBodyOffset();
        byte[] m_body = new byte[m_response.length - m_start];
        System.arraycopy(m_response, start, m_body, 0, m_response.length - start);



        if(!Arrays.equals(body, m_body) ){
            sout.println("可能存在xssi");
            issues.add(
                    new MessageFindIssue(
                            baseRequestResponse.getHttpService(),
                            helps.analyzeRequest(baseRequestResponse).getUrl(),
                            new IHttpRequestResponse[]{callbacks.applyMarkers(baseRequestResponse, null, null)},
                            "XSSI!",
                            "可能存在xssi漏洞",
                            "High"
                    )
            );
        }

        return  issues;
    }

    // 犹豫再三，由于jsonp的初步测试只需要发送一个包就行（之后手动验证），于是还是觉得放在被动扫描中
    public List<IScanIssue>  check_jsonp(List<IScanIssue> issues, IHttpRequestResponse baseRequestResponse){
        String jsonpmethod = "";
        Random r = new Random(8);
        Integer random = r.nextInt(99999999);
        Boolean isparameter = false;

        List<IParameter> originalParameters = helps.analyzeRequest(baseRequestResponse.getRequest()).getParameters();
        List<IParameter> parameters = helps.analyzeRequest(baseRequestResponse.getRequest()).getParameters();

        String host = baseRequestResponse.getHttpService().getHost();
        Integer port =baseRequestResponse.getHttpService().getPort();
        String protocol = baseRequestResponse.getHttpService().getProtocol();
        Boolean ishttps = false;
        if(protocol.equals("https")){
            ishttps = true;
        }

        byte[] request =baseRequestResponse.getRequest();
        IRequestInfo request_info = helps.analyzeRequest(request);


        // 判断是否带有请求callback字样的参数，替换value
        for(ListIterator<IParameter> iterator = parameters.listIterator();iterator.hasNext();){
             int i = iterator.nextIndex();
             IParameter currentParameter = iterator.next();
             if(jsonps.contains(currentParameter.getName())){
                 // 根据name替换value
                 parameters.set(i, helps.buildParameter(currentParameter.getName(),random.toString(),currentParameter.getType()));

                 jsonpmethod = currentParameter.getName();
                 isparameter = true;
                 break;
             }
        }

        // 第一种情况是url中带有类似的callback参数，其实还有一种情况是需要fuzz method name的，但是需要给所有请求都加一个额外的请求，想想还是算了
        if(isparameter){
            byte[] tempRequest = Arrays.copyOf(request, request.length);
            // 先删除所有参数
            for (IParameter param : originalParameters) {
                tempRequest = helps.removeParameter(tempRequest, param);
            }
            // 再添加所有参数
            for (IParameter param : parameters) {
                tempRequest = helps.addParameter(tempRequest, param);
            }
            IRequestInfo tempAnalyzedRequest = helps.analyzeRequest(tempRequest);
            byte[] body = Arrays
                    .copyOfRange(tempRequest, tempAnalyzedRequest.getBodyOffset(), tempRequest.length);
            List<String> headers = tempAnalyzedRequest.getHeaders();

            byte[] req = helps.buildHttpMessage(headers,body);
            byte[] resp = callbacks.makeHttpRequest(host,port,ishttps,req);

            List<int[]> matche = keywordMatch(resp, helps.stringToBytes(random.toString()), 0);
            if(matche.size() > 0){
                issues.add(
                        new JsonpIssue(
                                baseRequestResponse.getHttpService(),
                                helps.analyzeRequest(baseRequestResponse).getUrl(),
                                new IHttpRequestResponse[]{callbacks.applyMarkers(baseRequestResponse, null, matche)},
                                "Jsonp method find!",
                                "callback method: " + jsonpmethod,
                                "High"
                        )
                );
            }
        }

        return issues;
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