package org.verisign.joid.consumer;


import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * This filter will log a user in automatically if it sees the required openid
 * parameters in the request.
 *
 * User: treeder
 * Date: Jun 8, 2007
 * Time: 6:50:15 PM
 */
public class OpenIdFilter implements Filter {
	private static Log log = LogFactory.getLog(OpenIdFilter.class);
	private static JoidConsumer joid = new JoidConsumer();
	public static final String OPENID_ATTRIBUTE = "openid.identity"; // todo: remove one of these
	public static final String OPENID_IDENTITY = OPENID_ATTRIBUTE;
	boolean saveIdentityUrlAsCookie = false;
	private String cookieDomain;
    private List ignorePaths = new ArrayList();

    public void init(FilterConfig filterConfig) throws ServletException {
		log.debug("init OpenIdFilter");
		String saveInCookie = filterConfig.getInitParameter("saveInCookie");
		if(saveInCookie != null){
			saveIdentityUrlAsCookie = Boolean.parseBoolean(saveInCookie);
			log.debug("saving identities in cookie: " + saveIdentityUrlAsCookie);
		}
		cookieDomain = filterConfig.getInitParameter("cookieDomain");
        String ignorePaths = filterConfig.getInitParameter("ignorePaths");
        if(ignorePaths != null){
            String paths[] = ignorePaths.split(",");
            for (int i = 0; i < paths.length; i++)
            {
                String path = paths[i].trim();
                this.ignorePaths.add(path);
            }
        }
        log.debug("end init OpenIdFilter");
	}

	public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse,
                         FilterChain filterChain) throws IOException, ServletException {
		// basically just check for openId parameters
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        if (servletRequest.getParameter(OPENID_IDENTITY) != null && !ignored(request)) {
			try {
                AuthenticationResult result = joid.authenticate(convertToStringValueMap(servletRequest.getParameterMap()));
                String identity = result.getIdentity();
                if(identity != null){
                    HttpServletRequest req = (HttpServletRequest) servletRequest;
					req.getSession(true).setAttribute(OpenIdFilter.OPENID_ATTRIBUTE, identity);
					HttpServletResponse resp = (HttpServletResponse) servletResponse; // could check this before setting
					Cookie cookie = new Cookie(OPENID_IDENTITY, identity);
					if(cookieDomain != null){
						cookie.setDomain(cookieDomain);
					}
					resp.addCookie(cookie);
                    // redirect to get rid of the long url
                    resp.sendRedirect(result.getResponse().getReturnTo());
                    return;
                }
			} catch(AuthenticationException e){
                e.printStackTrace();
                log.info("auth failed: " + e.getMessage());
                // should this be handled differently?
            } catch(Exception e) {
				e.printStackTrace();
			}
		}
		filterChain.doFilter(servletRequest, servletResponse);
	}

    private boolean ignored(HttpServletRequest request)
    {
        String servletPath = request.getServletPath();
        for (int i = 0; i < ignorePaths.size(); i++)
        {
            String s = (String) ignorePaths.get(i);
            if(servletPath.startsWith(s)){
//                System.out.println("IGNORING: " + servletPath);
                return true;
            }
        }
        return false;
    }

    public static void logout(HttpSession session){
        session.removeAttribute(OPENID_ATTRIBUTE);
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
