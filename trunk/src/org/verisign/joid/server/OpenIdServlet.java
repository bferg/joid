package org.verisign.joid.server;

import org.apache.commons.logging.LogFactory;
import org.apache.commons.logging.Log;
import org.verisign.joid.AuthenticationRequest;
import org.verisign.joid.Crypto;
import org.verisign.joid.OpenId;
import org.verisign.joid.OpenIdException;
import org.verisign.joid.RequestFactory;
import org.verisign.joid.ServerInfo;
import org.verisign.joid.Store;
import org.verisign.joid.StoreFactory;
import org.verisign.joid.util.CookieUtils;
import org.verisign.joid.util.DependencyUtils;

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
    private static Log log = LogFactory.getLog(OpenIdServlet.class);
    private static final long serialVersionUID = 297366254782L;
    private static OpenId openId;
    private Store store;
    private Crypto crypto;
    private String loginPage;
    public static final String USERNAME_ATTRIBUTE = "username";
    public static final String ID_CLAIMED = "idClaimed";
    public static final String QUERY = "query";
    public static final String COOKIE_AUTH_NAME = "authKey";
    public static final String COOKIE_USERNAME = "username";
    private static UserManager userManager;

    public void init(ServletConfig config) throws ServletException
    {
        super.init(config);
        String storeClassName = config.getInitParameter("storeClassName");
        String userManagerClassName = config.getInitParameter("userManagerClassName");
        store = StoreFactory.getInstance(storeClassName);
        MemoryStore mStore = (MemoryStore) store;
        mStore.setAssociationLifetime(600);
        userManager = (UserManager) DependencyUtils.newInstance(userManagerClassName);
        crypto = new Crypto();
        loginPage = config.getInitParameter("loginPage");
        String endPointUrl = config.getInitParameter("endPointUrl");
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
        while (e.hasMoreElements()) {
            String name = (String) e.nextElement();
            String[] values = request.getParameterValues(name);
            if (values.length == 0) {
                throw new IOException("Empty value not allowed: "
                        + name + " has no value");
            }
            try {
                sb.append(URLEncoder.encode(name, "UTF-8") + "="
                        + URLEncoder.encode(values[0], "UTF-8"));
            } catch (UnsupportedEncodingException ex) {
                throw new IOException(ex.toString());
            }
            if (e.hasMoreElements()) {
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
        if (!(openId.canHandle(query))) {
            returnError(query, response);
            return;
        }
        try {
            boolean isAuth = openId.isAuthenticationRequest(query);
            HttpSession session = request.getSession(true);
            String user = getLoggedIn(request);
            System.out.println("[OpenIdServlet] Logged in as: " + user);
            if (isAuth && user == null) {
                // todo: should ask user to accept realm even if logged in, but only once
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
//                rd.forward(request, response);
                response.sendRedirect(loginPage);
                return;
            }
            String s = openId.handleRequest(query);
            log("\nresponse\n--------\n" + s + "\n");
            if (isAuth) {
                AuthenticationRequest authReq = (AuthenticationRequest)
                        RequestFactory.parse(query);
//                String claimedId = (String) session.getAttribute(ID_CLAIMED);
                /* Ensure that the previously claimed id is the same as the just
                passed in claimed id. */
                if (getUserManager().canClaim(user, authReq.getClaimedIdentity())) {
                    String returnTo = authReq.getReturnTo();
                    String delim = (returnTo.indexOf('?') >= 0) ? "&" : "?";
                    s = response.encodeRedirectURL(returnTo + delim + s);
                    response.sendRedirect(s);
                } else {
                    throw new OpenIdException("User cannot claim this id.");
                }

            } else {
                // Association request
                int len = s.length();
                PrintWriter out = response.getWriter();
                response.setHeader("Content-Length", Integer.toString(len));
                if (openId.isAnErrorResponse(s)) {
                    response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                }
                out.print(s);
                out.flush();
            }
        } catch (OpenIdException e) {
            e.printStackTrace();
            response.sendError(HttpServletResponse
                    .SC_INTERNAL_SERVER_ERROR, e.getMessage());
        }
    }

    /**
     *
     * @param request
     * @return Username the user is logged in as
     */
    public static String getLoggedIn(HttpServletRequest request)
    {
        String o = (String) request.getSession(true).getAttribute(USERNAME_ATTRIBUTE);
        if (o != null) return o;
        // check Remember Me cookies
        String authKey = CookieUtils.getCookieValue(request, COOKIE_AUTH_NAME, null);
        if (authKey != null) {
            String username = CookieUtils.getCookieValue(request, COOKIE_USERNAME, null);
            if (username != null) {
                // lets check the UserManager to make sure this is a valid match
                o = getUserManager().getRememberedUser(username, authKey);
                if (o != null) {
                    request.getSession(true).setAttribute(USERNAME_ATTRIBUTE, o);
                }
            }
        }
        return o;
    }

    /**
     *
     * @param request
     * @param username if null, will logout
     */
    public static void setLoggedIn(HttpServletRequest request, String username){
        request.getSession(true).setAttribute(USERNAME_ATTRIBUTE, username);
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
        } catch (MalformedURLException e) {
            e.printStackTrace();
        }

        if (goodReturnTo) {
            String s = "?openid.ns:http://specs.openid.net/auth/2.0"
                    + "&openid.mode=error&openid.error=BAD_REQUEST";
            s = response.encodeRedirectURL(returnTo + s);
            response.sendRedirect(s);
        } else {
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

    public static UserManager getUserManager()
    {
        return userManager;
    }
}
