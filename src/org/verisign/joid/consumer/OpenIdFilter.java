package org.verisign.joid.consumer;


import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.Cookie;
import java.util.logging.Logger;
import java.util.Map;
import java.util.Set;
import java.util.Iterator;
import java.util.HashMap;
import java.io.IOException;

/**
 * User: treeder
 * Date: Jun 8, 2007
 * Time: 6:50:15 PM
 */
public class OpenIdFilter implements Filter {
	private static Logger logger = Logger.getLogger(OpenIdFilter.class.getName());
	private FilterConfig filterConf;
	private ServletContext servletContext;
	static JoidConsumer joid = new JoidConsumer();
	public static final String OPENID_ATTRIBUTE = "openid.identity"; // todo: remove one of these
	public static final String OPENID_IDENTITY = OPENID_ATTRIBUTE;
	boolean saveIdentityUrlAsCookie = false;
	private String cookieDomain;

	public void init(FilterConfig filterConfig) throws ServletException {
		System.out.println("init OpenIdFilter");
		this.filterConf = filterConfig;
		this.servletContext = filterConfig.getServletContext();
		String saveInCookie = filterConfig.getInitParameter("saveInCookie");
		if(saveInCookie != null){
			saveIdentityUrlAsCookie = Boolean.parseBoolean(saveInCookie);
			System.out.println("saving identities in cookie: " + saveIdentityUrlAsCookie);
		}
		cookieDomain = filterConfig.getInitParameter("cookieDomain");
		System.out.println("end init OpenIdFilter");
	}

	public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
		// basically just check for openId parameters
		if (servletRequest.getParameter(OPENID_IDENTITY) != null) {
			try {
				String identity = joid.authenticate(convertToStringValueMap(servletRequest.getParameterMap()));
				if(identity != null){
					HttpServletRequest req = (HttpServletRequest) servletRequest;
					req.getSession(true).setAttribute(OpenIdFilter.OPENID_ATTRIBUTE, identity);
					HttpServletResponse resp = (HttpServletResponse) servletResponse; // could check this before setting
					Cookie cookie = new Cookie(OPENID_IDENTITY, identity);
					if(cookieDomain != null){
						cookie.setDomain(cookieDomain);
					}
					resp.addCookie(cookie);
				}
			} catch(AuthenticationException e){
				System.out.println("auth failed: " + e.getMessage());
			} catch(Exception e) {
				e.printStackTrace();
			}
		}
		filterChain.doFilter(servletRequest, servletResponse);
	}

	private Map/*<String, String>*/ convertToStringValueMap(Map/*<String, String[]>*/ parameterMap) {
		Map/*<String,String>*/ ret = new HashMap();
		Set set = parameterMap.entrySet();
		for (Iterator iter = set.iterator(); iter.hasNext();) {
			Map.Entry mapEntry = (Map.Entry) iter.next();
			String key = (String) mapEntry.getKey();
			String[] value = (String[]) mapEntry.getValue();
			ret.put(key, value[0]);
		}
		return ret;
	}

	public void destroy() {

	}

	public static JoidConsumer joid() {
		return joid;
	}

	public static String getCurrentUser(HttpSession session) {
		return (String) session.getAttribute(OpenIdFilter.OPENID_ATTRIBUTE);
	}
}
