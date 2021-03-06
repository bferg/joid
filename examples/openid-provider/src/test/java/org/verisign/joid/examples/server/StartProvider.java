package org.verisign.joid.examples.server;

import org.mortbay.jetty.Connector;
import org.mortbay.jetty.Server;
import org.mortbay.jetty.bio.SocketConnector;
import org.mortbay.jetty.webapp.WebAppContext;

/**
 * 
 * A runnable test class that enables openid provider application in an embedded Jetty container
 *
 * @author <a href="mailto:birkan.duman@gmail.com">Birkan Duman</a>
 */
public class StartProvider {

	public static void main(String[] args) throws Exception {
		Server server = new Server();
		SocketConnector connector = new SocketConnector();
		
		// Set some timeout options to make debugging easier.
//		connector.setMaxIdleTime(1000 * 60 * 60);
//		connector.setSoLingerTime(-1);
		connector.setPort(8180);
		server.setConnectors(new Connector[] { connector });

		WebAppContext bb = new WebAppContext();
		bb.setClassLoader( Thread.currentThread().getContextClassLoader() );
		bb.setServer(server);
		bb.setContextPath("/");
		bb.setWar("src/main/webapp");
		
		// START JMX SERVER
		// MBeanServer mBeanServer = ManagementFactory.getPlatformMBeanServer();
		// MBeanContainer mBeanContainer = new MBeanContainer(mBeanServer);
		// server.getContainer().addEventListener(mBeanContainer);
		// mBeanContainer.start();
		
		server.addHandler(bb);

		try {
			System.out.println(">>> STARTING EMBEDDED JETTY SERVER, PRESS ANY KEY TO STOP");
			server.start();
			System.in.read();
			System.out.println(">>> STOPPING EMBEDDED JETTY SERVER"); 
            // while (System.in.available() == 0) {
			//   Thread.sleep(5000);
			// }
			server.stop();
			server.join();
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(100);
		}
	}
}
