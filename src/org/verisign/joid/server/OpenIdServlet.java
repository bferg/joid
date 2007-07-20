package org.verisign.joid.server;

import org.verisign.joid.server.MemoryUserManager;
import org.verisign.joid.server.MemoryStore;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.RequestDispatcher;

import org.verisign.joid.*;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.io.PrintWriter;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.URL;
import java.net.MalformedURLException;
import java.util.Enumeration;
import java.util.Map;

/**
 * User: treeder
 * Date: Jul 18, 2007
 * Time: 4:50:33 PM
 */
public class OpenIdServlet extends HttpServlet {
	private static final long serialVersionUID = 297366254782L;
	private static OpenId openId;
	private Store store;
	private Crypto crypto;
	private MemoryUserManager userManager;
	private String loginPage;

	public void init(ServletConfig config) throws ServletException {
		super.init(config);
		store = StoreFactory.getInstance(MemoryStore.class.getName());
		crypto = new Crypto();
		String endPointUrl = config.getInitParameter("endPointUrl");
		loginPage = config.getInitParameter("loginPage");
		openId = new OpenId(new ServerInfo(endPointUrl, store, crypto));
		userManager = new MemoryUserManager();
	}


	public void doGet(HttpServletRequest request,
	                  HttpServletResponse response)
			throws ServletException, IOException {
		doQuery(request.getQueryString(), request, response);
	}

	public void doPost(HttpServletRequest request,
	                   HttpServletResponse response)
			throws ServletException, IOException {
		// check if user is logging in.
		String username = request.getParameter("username");
		if(username != null){
			authenticate(request, username, request.getParameter("password"), request.getParameter("newuser"));
			doQuery(URLDecoder.decode(request.getParameter("query")), request, response);
			return;
		}
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

	private void authenticate(HttpServletRequest request, String username, String password, String newuser) {
		User user = userManager.getUser(username);
		if(user == null){
			if(newuser != null){
				user = new User(username, password);
				userManager.save(user);
				System.out.println("created new user");
			} else {
				return;
			}
		}
		if(user.getPassword().equals(password)){
			request.getSession(true).setAttribute("user", user);
		}
	}

	public void doQuery(String query,
	                    HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {
		log("\nrequest\n-------\n" + query + "\n");
		if (!(openId.canHandle(query))) {
			returnError(query, response);
			return;
		}
		try {
			boolean isAuth = openId.isAuthenticationRequest(query);
			if (isAuth && !loggedIn(request)) {
				// ask user to accept this realm
				RequestDispatcher rd = request.getRequestDispatcher(loginPage);
				request.setAttribute("query", query);
				request.setAttribute("openid.realm", request.getParameter("openid.realm"));
				rd.forward(request, response);
				return;
			}
			String s = openId.handleRequest(query);
			log("\nresponse\n--------\n" + s + "\n");
			if (isAuth) {
				AuthenticationRequest authReq = (AuthenticationRequest)
						RequestFactory.parse(query);
				String returnTo = authReq.getReturnTo();
				String delim = (returnTo.indexOf('?') >= 0) ? "&" : "?";
				s = response.encodeRedirectURL(returnTo + delim + s);
				response.sendRedirect(s);
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
			response.sendError(HttpServletResponse
					.SC_INTERNAL_SERVER_ERROR);
		}
	}

	private boolean loggedIn(HttpServletRequest request) {
		return request.getSession(true).getAttribute("user") != null;
	}

	private void returnError(String query, HttpServletResponse response)
			throws ServletException, IOException {
		Map map = RequestFactory.parseQuery(query);
		String returnTo = (String) map.get("openid.return_to");
		boolean goodReturnTo = false;
		try {
			URL url = new URL(returnTo);
			goodReturnTo = true;
		} catch (MalformedURLException e) {
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

	public void log(String s) {
		// todo: resolve issue with non-prime servlet container + log4j/commons and replace
		System.out.println(s);
	}
}
