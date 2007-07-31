<%@ page import="org.verisign.joid.util.UrlUtils" %>
<%
	String baseUrl = UrlUtils.getBaseUrl(request);
	String openIdServer = baseUrl + "/login";
    String username = (String) request.getAttribute("username");
%>
<html>
<head>
	<title><%=username%>'s OpenId Identity Page</title>
	<link rel="openid.server" href="<%=openIdServer%>">

</head>
<body>
<h1><%=username%>'s OpenID Identity Page</h1>
<p>
This is a sample OpenID identity page. It contains a &lt;link&gt; tag with the OpenID server.
</p>

</body>
</html>