<%@ page import="org.verisign.joid.server.MemoryUserManager" %>
<%@ page import="java.net.URLDecoder" %>
<%@ page import="org.verisign.joid.server.User" %>
<%@ page import="org.verisign.joid.server.OpenIdServlet" %>
<%@ page import="org.verisign.joid.util.UrlUtils" %>
<%!
	private String getParam(HttpServletRequest request, String s) {
		String ret = (String) request.getAttribute(s);
		if (ret == null) {
			ret = request.getParameter(s);
		}
		return ret;
	}

	private MemoryUserManager userManager = new MemoryUserManager();

	private boolean authenticate(HttpServletRequest request, String username, String password, String newuser) {
		User user = userManager.getUser(username);
		if (user == null) {
			if (newuser != null) {
				user = new User(username, password);
				userManager.save(user);
				System.out.println("created new user");
			} else {
				return false;
			}
		}
		if (user.getPassword().equals(password)) {
			request.getSession(true).setAttribute(OpenIdServlet.USER_ATTRIBUTE, user);
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
			String query = request.getParameter("query");
//			doQuery(URLDecoder.decode(), request, response);
			// then we'll redirect to login servlet again
			String baseUrl = UrlUtils.getBaseUrl(request);
			String openIdServer = baseUrl + "/login";
			response.sendRedirect(openIdServer + "?" + URLDecoder.decode(query));
			return;
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
			font-weight:bold;
			color:red;
		}
	</style>
</head>
<body>
<%
	if(errorMsg != null){
%>
<div class="error"><%=errorMsg%></div>
<%
	}
%>
<form action="login.jsp" method="post">
	<input type="hidden" name="query" value="<%=getParam(request, "query")%>" />
	<input type="hidden" name="openid.realm" value="<%=getParam(request, "openid.realm")%>" />
	<p>
Allow access to: <%=request.getAttribute("openid.realm")%>?
	</p>
	<table border="0">
		<tr>
			<td>Username:</td>
			<td><input type="text" name="username" /></td>
		</tr>
		<tr>
			<td>Password:</td>
			<td><input type="password" name="password" /></td>
		</tr>
		<tr>
			<td>Create New User?</td>
			<td><input type="checkbox" name="newuser" /></td>
		</tr>
		<tr>
			<td>&nbsp;</td>
			<td><input type="submit" value="Submit" /></td>
		</tr>
	</table>
</form>
<p>
Logged in as: <%=session.getAttribute("user")%>
</p>

</body>
</html>