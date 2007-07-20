package org.verisign.joid.util;

import javax.servlet.http.HttpServletRequest;

/**
 * User: treeder
 * Date: Jul 19, 2007
 * Time: 4:05:35 PM
 */
public class UrlUtils {
	/**
	 *
	 * @param request
	 * @return the url of the local host including the context
	 */
	public static String getBaseUrl(HttpServletRequest request) {
		String scheme = request.getScheme();
		String serverName = request.getServerName();
		String port = request.getServerPort() != 80 ? ":" + request.getServerPort() : "";
		String context = request.getContextPath();
		String returnTo = scheme + "://" + serverName + port + context;
		return returnTo;
	}
}
