<%--
This page is a sample login page for OpenID SERVERS. You only need this if you are an OpenID provider. Consumers do NOT need this page.
--%>
<%@ page contentType="text/html;charset=UTF-8" language="java"%>
<%@ page import="org.apache.commons.lang.RandomStringUtils" %>
<%@ page import="org.verisign.joid.AuthenticationRequest" %>
<%@ page import="org.verisign.joid.server.MemoryUserManager" %>
<%@ page import="org.verisign.joid.server.OpenIdServlet" %>
<%@ page import="org.verisign.joid.server.User" %>
<%@ page import="org.verisign.joid.util.CookieUtils" %>
<%@ page import="org.verisign.joid.util.UrlUtils" %>
<%@ page import="java.net.URLDecoder" %>

<%!
    
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

<form action="/authenticate" method="post" accept-charset="utf-8">
    <input type="hidden" name="query" value="<%=getParam(request, "query")%>"/>
    <input type="hidden" name="openid.realm"
           value="<%=getParam(request, "openid.realm")%>"/>

    <p>
        Allow access to: <a href="<%=getParam(request, "openid.realm")%>"
                    target="_blank"><%=getParam(request, "openid.realm")%></a>?
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