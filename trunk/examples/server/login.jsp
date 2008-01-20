<%@ page import="org.apache.commons.lang.RandomStringUtils" %>
<%@ page import="org.verisign.joid.AuthenticationRequest" %>
<%@ page import="org.verisign.joid.server.MemoryUserManager" %>
<%@ page import="org.verisign.joid.server.OpenIdServlet" %>
<%@ page import="org.verisign.joid.server.User" %>
<%@ page import="org.verisign.joid.util.CookieUtils" %>
<%@ page import="org.verisign.joid.util.UrlUtils" %>
<%@ page import="java.net.URLDecoder" %>
<%!
    private MemoryUserManager userManager()
    {
        return (MemoryUserManager) OpenIdServlet.getUserManager();
    }

    private String getParam(HttpServletRequest request, String s)
    {
        String ret = (String) request.getAttribute(s);
        if (ret == null) {
            ret = request.getParameter(s);
        }
        // then try session
        if(ret == null){
            HttpSession session = request.getSession(true);
            ret = (String) session.getAttribute(s);
        }
        return ret;
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
%>
<%
    String errorMsg = null;
    // check if user is logging in.
    String username = request.getParameter("username");
    if (username != null) {
        if (authenticate(request, username, request.getParameter("password"), request.getParameter("newuser"))) {
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
                    String query = request.getParameter("query");
                    // then we'll redirect to login servlet again to finish up
                    String baseUrl = UrlUtils.getBaseUrl(request);
                    String openIdServer = baseUrl + "/login";
                    response.sendRedirect(openIdServer + "?" + URLDecoder.decode(query));
                    return;
                } else {
                    errorMsg = "You do not own the claimed identity.";
                }
            }
            if(request.getParameter("rememberMe") != null){
                // store username and secret key combo for later retrieval and set cookies
                String secretKey = RandomStringUtils.randomAlphanumeric(128);
                CookieUtils.setCookie(response, OpenIdServlet.COOKIE_USERNAME, username);
                CookieUtils.setCookie(response, OpenIdServlet.COOKIE_AUTH_NAME, secretKey);
                userManager().remember(username, secretKey);
            }
        } else {
            // error for user side
            errorMsg = "Invalid login.";
        }
    }
%>
<html>
<head>
    <style type="text/css">
        .error {
            font-weight: bold;
            color: red;
        }
    </style>
</head>
<body>
<%
    if (errorMsg != null) {
%>
<div class="error"><%=errorMsg%>
</div>
<%
    }
%>
<form action="login.jsp" method="post">
    <input type="hidden" name="query" value="<%=getParam(request, "query")%>"/>
    <input type="hidden" name="openid.realm"
           value="<%=getParam(request, "openid.realm")%>"/>

    <p>
        Allow access to: <%=getParam(request, "openid.realm")%>?
    </p>
    <table border="0">
        <tr>
            <td>Username:</td>
            <td><input type="text" name="username"/></td>
        </tr>
        <tr>
            <td>Password:</td>
            <td><input type="password" name="password"/></td>
        </tr>
        <tr>
            <td>Create New User?</td>
            <td><input type="checkbox" name="newuser"/></td>
        </tr>
         <tr>
            <td>Remember Me?</td>
            <td><input type="checkbox" name="rememberMe"/></td>
        </tr>
        <tr>
            <td>&nbsp;</td>
            <td><input type="submit" value="Submit"/></td>
        </tr>
    </table>
</form>
<p>
    Logged in as: <%=session.getAttribute("user")%>
</p>

</body>
</html>
