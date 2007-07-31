<%@ page import="org.verisign.joid.consumer.OpenIdFilter"%><%
	session.removeAttribute(OpenIdFilter.OPENID_ATTRIBUTE);
	session.removeAttribute("user");
	session.invalidate();
	response.sendRedirect(request.getContextPath() + "/index.jsp");
%>