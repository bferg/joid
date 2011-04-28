package org.verisign.joid.examples.server;

import java.io.IOException;
import java.net.URLDecoder;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.lang.RandomStringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.verisign.joid.AuthenticationRequest;
import org.verisign.joid.server.MemoryUserManager;
import org.verisign.joid.server.OpenIdServlet;
import org.verisign.joid.server.User;
import org.verisign.joid.util.CookieUtils;
import org.verisign.joid.util.UrlUtils;

public class ProviderServlet extends HttpServlet
{
    
    private final Log LOG = LogFactory.getLog( ProviderServlet.class );
    
    @Override
    protected void doPost( HttpServletRequest req, HttpServletResponse resp ) throws ServletException, IOException
    {
        LOG.debug( "doPost()" );

        String returnTo = UrlUtils.getBaseUrl( req );
        String trustRoot = "http://localhost:8180";//@TODO make as an init param
        
        HttpSession  session = req.getSession();
        
        try
        {
            String errorMsg = null;
            // check if user is logging in.
            String username = req.getParameter("username");
            if (username != null) {
                if (authenticate(req, username, req.getParameter("password"), req.getParameter("newuser"))) {
                    // ensure this user owns the claimed identity
                    String claimedId = (String) session.getAttribute(AuthenticationRequest.OPENID_CLAIMED_ID);
                    if (claimedId != null) {
                        // for this example app, the authenticated user must match the last
                        // section of the openid.claimed_id, ie: /user/username
                        String usernameFromClaimedId = claimedId.substring(claimedId.lastIndexOf("/") + 1);
                        System.out.println("usernamefromurl: " + usernameFromClaimedId);
                        if (username.equals(usernameFromClaimedId)) {
                            // call this to verify that this user owns the claimed_id
                            // todo: perhaps the claim(s) should be attached to the User object
                            OpenIdServlet.idClaimed(session, claimedId);
                            String query = req.getParameter("query");
                            // then we'll redirect to login servlet again to finish up
                            String baseUrl = UrlUtils.getBaseUrl(req);
                            String openIdServer = baseUrl + "/login";
                            resp.sendRedirect(openIdServer + "?" + URLDecoder.decode(query));
                            return;
                        } else {
                            errorMsg = "You do not own the claimed identity.";
                        }
                    }
                    if(req.getParameter("rememberMe") != null){
                        // store username and secret key combo for later retrieval and set cookies
                        String secretKey = RandomStringUtils.randomAlphanumeric(128);
                        CookieUtils.setCookie(resp, OpenIdServlet.COOKIE_USERNAME, username);
                        CookieUtils.setCookie(resp, OpenIdServlet.COOKIE_AUTH_NAME, secretKey);
                        userManager().remember(username, secretKey);
                    }
                } else {
                    // error for user side
                    errorMsg = "Invalid login.";
                }
            }
        }
        catch ( Throwable e )
        {
            LOG.error( e.getMessage() );
        }

    }
    
    private boolean authenticate(HttpServletRequest request, String username, String password, String newuser)
    {
        User user = userManager().getUser(username);
        if (user == null) {
            if (newuser != null) {
                user = new User(username, password);
                userManager().save(user);
                System.out.println("created new user: " + username);
            } else {
                return false;
            }
        }
        if (user.getPassword().equals(password)) {
            request.getSession(true).setAttribute(OpenIdServlet.USERNAME_ATTRIBUTE, user.getUsername());
            request.getSession(true).setAttribute("user", user);
            return true;
        }
        return false;
    }
    
    private MemoryUserManager userManager()
    {
        return (MemoryUserManager) OpenIdServlet.getUserManager();
    }

    
    
    private static final long serialVersionUID = -7100990612067175777L;
}