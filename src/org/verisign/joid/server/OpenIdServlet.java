package org.verisign.joid.server;

import org.verisign.joid.*;
import org.apache.log4j.Logger;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.util.Enumeration;
import java.util.Map;

/**
 * User: treeder
 * Date: Jul 18, 2007
 * Time: 4:50:33 PM
 */
public class OpenIdServlet extends HttpServlet
{
    private static Logger log = Logger.getLogger(OpenIdServlet.class);
    private static final long serialVersionUID = 297366254782L;
    private static OpenId openId;
    private Store store;
    private Crypto crypto;
    private String loginPage;
    public static final String USER_ATTRIBUTE = "user";
    public static final String ID_CLAIMED = "idClaimed";
    public static final String QUERY = "query";

    public void init(ServletConfig config) throws ServletException
    {
        super.init(config);
        store = StoreFactory.getInstance(MemoryStore.class.getName());
        crypto = new Crypto();
        String endPointUrl = config.getInitParameter("endPointUrl");
        loginPage = config.getInitParameter("loginPage");
        openId = new OpenId(new ServerInfo(endPointUrl, store, crypto));
    }


    public void doGet(HttpServletRequest request,
                      HttpServletResponse response)
            throws ServletException, IOException
    {
        doQuery(request.getQueryString(), request, response);
    }

    public void doPost(HttpServletRequest request,
                       HttpServletResponse response)
            throws ServletException, IOException
    {
        StringBuffer sb = new StringBuffer();
        Enumeration e = request.getParameterNames();
        while (e.hasMoreElements())
        {
            String name = (String) e.nextElement();
            String[] values = request.getParameterValues(name);
            if (values.length == 0)
            {
                throw new IOException("Empty value not allowed: "
                        + name + " has no value");
            }
            try
            {
                sb.append(URLEncoder.encode(name, "UTF-8") + "="
                        + URLEncoder.encode(values[0], "UTF-8"));
            } catch (UnsupportedEncodingException ex)
            {
                throw new IOException(ex.toString());
            }
            if (e.hasMoreElements())
            {
                sb.append("&");
            }
        }
        doQuery(sb.toString(), request, response);
    }


    public void doQuery(String query,
                        HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException
    {
        log("\nrequest\n-------\n" + query + "\n");
        if (!(openId.canHandle(query)))
        {
            returnError(query, response);
            return;
        }
        try
        {
            boolean isAuth = openId.isAuthenticationRequest(query);
            HttpSession session = request.getSession(true);
            if (isAuth && !loggedIn(request))
            {
                // ask user to accept this realm
                RequestDispatcher rd = request.getRequestDispatcher(loginPage);
                request.setAttribute(QUERY, query);
                request.setAttribute(AuthenticationRequest.OPENID_REALM, request.getParameter(AuthenticationRequest.OPENID_REALM));
                // would it be better to store these in the session? Much better for ajaxy apps
                session.setAttribute(QUERY, query);
                session.setAttribute(
                        AuthenticationRequest.OPENID_CLAIMED_ID,
                        request.getParameter(AuthenticationRequest.OPENID_CLAIMED_ID));
                session.setAttribute(
                        AuthenticationRequest.OPENID_REALM,
                        request.getParameter(AuthenticationRequest.OPENID_REALM));
                session.setAttribute(
                        AuthenticationRequest.OPENID_RETURN_TO,
                        request.getParameter(AuthenticationRequest.OPENID_RETURN_TO));
                rd.forward(request, response);
                return;
            }
            String s = openId.handleRequest(query);
            log("\nresponse\n--------\n" + s + "\n");
            if (isAuth)
            {
                AuthenticationRequest authReq = (AuthenticationRequest)
                        RequestFactory.parse(query);
                String claimedId = (String) session.getAttribute(ID_CLAIMED);
                log.info("claimedId: " + claimedId);
                if (claimedId != null && claimedId.equals(authReq.getClaimedIdentity()))
                {
                    String returnTo = authReq.getReturnTo();
                    String delim = (returnTo.indexOf('?') >= 0) ? "&" : "?";
                    s = response.encodeRedirectURL(returnTo + delim + s);
                    response.sendRedirect(s);
                } else {
                    throw new OpenIdException("The claimed id has not been verified.");
                }
            } else
            {
                // Association request
                int len = s.length();
                PrintWriter out = response.getWriter();
                response.setHeader("Content-Length", Integer.toString(len));
                if (openId.isAnErrorResponse(s))
                {
                    response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                }
                out.print(s);
                out.flush();
            }
        } catch (OpenIdException e)
        {
            e.printStackTrace();
            response.sendError(HttpServletResponse
                    .SC_INTERNAL_SERVER_ERROR, e.getMessage());
        }
    }

    private boolean loggedIn(HttpServletRequest request)
    {
        return request.getSession(true).getAttribute(USER_ATTRIBUTE) != null;
    }

    private void returnError(String query, HttpServletResponse response)
            throws ServletException, IOException
    {
        Map map = RequestFactory.parseQuery(query);
        String returnTo = (String) map.get("openid.return_to");
        boolean goodReturnTo = false;
        try
        {
            URL url = new URL(returnTo);
            goodReturnTo = true;
        } catch (MalformedURLException e)
        {
        }

        if (goodReturnTo)
        {
            String s = "?openid.ns:http://specs.openid.net/auth/2.0"
                    + "&openid.mode=error&openid.error=BAD_REQUEST";
            s = response.encodeRedirectURL(returnTo + s);
            response.sendRedirect(s);
        } else
        {
            PrintWriter out = response.getWriter();
            // response.setContentLength() seems to be broken,
            // so set the header manually
            String s = "ns:http://specs.openid.net/auth/2.0\n"
                    + "&mode:error"
                    + "&error:BAD_REQUEST\n";
            int len = s.length();
            response.setHeader("Content-Length", Integer.toString(len));
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            out.print(s);
            out.flush();
        }
    }

    public void log(String s)
    {
        // todo: resolve issue with non-prime servlet container + log4j/commons and replace
        System.out.println(s);
    }

    /**
     * This sets a session variable stating that the claimed_id for this request
     * has been verified so we can now return back to the relying party.
     *
     * @param session
     * @param claimedId
     */
    public static void idClaimed(HttpSession session, String claimedId)
    {
        session.setAttribute(ID_CLAIMED, claimedId);
    }
}
