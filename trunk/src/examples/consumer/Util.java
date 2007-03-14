package examples.consumer;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import org.verisign.joid.OpenIdException;
import org.verisign.joid.Request;
import org.verisign.joid.Response;
import org.verisign.joid.ResponseFactory;

public class Util
{
    public static Response send(Request req, String dest) 
	throws IOException, OpenIdException
    {
	String toSend = req.toUrlString();
	StringBuffer b = new StringBuffer();
	
	BufferedReader in = null;
	try {
	    URL url = new URL(dest+"?"+toSend);
	    HttpURLConnection.setFollowRedirects(true);
	    HttpURLConnection connection 
		= (HttpURLConnection) url.openConnection();
	    
	    in = new BufferedReader(new InputStreamReader(connection
							  .getInputStream()));
	    String str;
	    while ((str = in.readLine()) != null) {
		b.append(str);
		b.append('\n');
	    }  
	} finally {
	    if (in != null) in.close();
	}
	return ResponseFactory.parse(b.toString());
    }
}

