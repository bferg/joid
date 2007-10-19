package examples.server;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.util.Enumeration;
import java.util.Map;
import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.verisign.joid.Crypto;
import org.verisign.joid.OpenId;
import org.verisign.joid.OpenIdException;
import org.verisign.joid.RequestFactory;
import org.verisign.joid.Store;
import org.verisign.joid.StoreFactory;

public class OpenIdServlet extends HttpServlet
{    
    private static final long serialVersionUID = 297366254782L;
    private static OpenId openId;
    private Store store;
    private Crypto crypto;
    
    public void init(ServletConfig config) throws ServletException
    {
	super.init(config);
        store = StoreFactory.getInstance(MemoryStore.class.getName());
        crypto = new Crypto();
        openId = new OpenId(store);
    }

    
    public void doGet(HttpServletRequest request, 
                        HttpServletResponse response)
        throws ServletException, IOException
    {
	doQuery(request.getQueryString(), response);
    }

    public void doPost(HttpServletRequest request, 
                        HttpServletResponse response)
        throws ServletException, IOException
    {
	StringBuffer sb = new StringBuffer();
	Enumeration e = request.getParameterNames();
	while (e.hasMoreElements()) {
	    String name = (String) e.nextElement();
	    String[] values = request.getParameterValues(name);
	    if (values.length == 0) {
		throw new IOException("Empty value not allowed: "
					  +name+ " has no value");
	    }
	    try {
		sb.append(URLEncoder.encode(name, "UTF-8")+"="
			  +URLEncoder.encode(values[0], "UTF-8"));
	    } catch (UnsupportedEncodingException ex){
		throw new IOException(ex.toString());
	    }
	    if (e.hasMoreElements()) {
		sb.append("&");
	    }
	}
	doQuery(sb.toString(), response);
    }

    public void doQuery(String query, 
                        HttpServletResponse response)
        throws ServletException, IOException
    {
	if (!(openId.canHandle(query))){
	    returnError(query, response);
	    return;
	}
        
	try {
	    String s = openId.handleRequest(query);
	    if (openId.isAuthenticationRequest(query)) {
		Map map = RequestFactory.parseQuery(query); 
		String return_to = (String) map.get("openid.return_to");
		String delim = (return_to.indexOf('?') >= 0) ? "&" : "?"; 
		s = response.encodeRedirectURL(return_to + delim + s);
		log("S="+s);
		response.sendRedirect(s);
	    } else {
		int len = s.length();
		PrintWriter out = response.getWriter();
		response.setHeader("Content-Length",Integer.toString(len));
		if (openId.isAnErrorResponse(s)){
		    response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
		}
		out.print(s);
		out.flush();
	    }
	    return;             
	} catch (OpenIdException e) {
	    response.sendError(HttpServletResponse
			       .SC_INTERNAL_SERVER_ERROR);
	}
    }


    private void returnError(String query, HttpServletResponse response)
        throws ServletException, IOException
    {
        Map map = RequestFactory.parseQuery(query); 
        String returnTo = (String) map.get("openid.return_to");
        boolean goodReturnTo = false;
        try {
            URL url = new URL(returnTo);
            goodReturnTo = true;
        } catch (MalformedURLException e){
        }

        if (goodReturnTo) {
            String s = "?openid.ns:http://openid.net/signon/2.0"
                +"&openid.mode=error&openid.error=BAD_REQUEST";
            s = response.encodeRedirectURL(returnTo+s);
            response.sendRedirect(s);
        } else {
            PrintWriter out = response.getWriter();
            // response.setContentLength() seems to be broken, 
            // so set the header manually 
            String s = "ns:http://openid.net/signon/2.0\n"
                +"&mode:error"
                +"&error:BAD_REQUEST\n";
            int len = s.length();
            response.setHeader("Content-Length",Integer.toString(len));
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            out.print(s);
            out.flush();
        }
    }

    public void log(String s)
    {
	// resolve issue with non-prime servlet container + log4j/commons
	// and replace
	System.out.println(s);
    }
}

