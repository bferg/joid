<html>
<head></head>
<body>

<form action="<%=request.getContextPath()%>/login" method="post">
	<input type="hidden" name="query" value="<%=request.getAttribute("query")%>" />
	<input type="hidden" name="openid.realm" value="<%=request.getAttribute("openid.realm")%>" />
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