package org.verisign.joid.consumer;

import org.verisign.joid.OpenIdException;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

/**
 *
 * User: treeder
 * Date: Jul 17, 2007
 * Time: 5:05:52 PM
 */
public class Discoverer {

    public ServerAndDelegate findIdServer(String identityUrl)
            throws IOException, OpenIdException
    {
		ServerAndDelegate serverAndDelegate = new ServerAndDelegate();
		BufferedReader in = null;
		try {
			URL url = new URL(identityUrl);
			HttpURLConnection.setFollowRedirects(true);
			HttpURLConnection connection
					= (HttpURLConnection) url.openConnection();

			in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
			String str;
			while ((str = in.readLine()) != null) {
				if(serverAndDelegate.getServer() == null) {
					serverAndDelegate.setServer(findLinkTag(str, "openid.server", in));
				}
				if(serverAndDelegate.getDelegate() == null) {
					serverAndDelegate.setDelegate(findLinkTag(str, "openid.delegate", in));
				}
				if(str.indexOf("</head>") >= 0){
					break;
				}
			}
		} finally {
			if (in != null) in.close();
		}
        if(serverAndDelegate.getServer() == null){
            throw new OpenIdException("No openid.server found on identity page.");
        }
        return serverAndDelegate;
	}

	private String findLinkTag(String str, String rel, BufferedReader in)
            throws IOException {
		int index = str.indexOf(rel);
		if(index != -1){
			// todo: ensure it's a proper link tag
			// todo: allow multiple line tag
			// todo: allow reverse ordering
			String href = findHref(str, index);
			if(href == null) {
				// no href found, check next line
				str = in.readLine();
				if(str != null){
					href = findHref(str, 0);
				}
			}
			return href;
		}
		return null;
	}

	private String findHref(String str, int index) {
		String href = null;
		int indexOfHref = str.indexOf("href=", index);
		if(indexOfHref != -1){
			href = str.substring(indexOfHref + 6, str.indexOf("\"", indexOfHref + 8));
		}
		return href;
	}
}
