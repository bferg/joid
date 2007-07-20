<%@ page import="org.verisign.joid.util.UrlUtils" %>
<%
	String baseUrl = UrlUtils.getBaseUrl(request);
	String openIdServer = baseUrl + "/login";
%>
<html>
<head>
	<title>Someone's OpenId Identity Page</title>
	<link rel="openid.server" href="<%=openIdServer%>">

</head>
<body>
<h1>Someones OpenID Identity Page</h1>
<p>
This is a sample OpenID identity page. It contains a &lt;link&gt; tag with the OpenID server.
</p>

</body>
</html>