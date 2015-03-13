## Introduction ##

There are two pieces required to run the server:

  1. A Store implementation - example: [MemoryStore](http://joid.googlecode.com/svn/trunk/src/org/verisign/joid/server/MemoryStore.java)
  1. A Servlet - example: [OpenIdServlet](http://joid.googlecode.com/svn/trunk/src/examples/server/OpenIdServlet.java)
  1. A [UserManager](http://joid.googlecode.com/svn/trunk/src/org/verisign/joid/server/UserManager.java) Implementation

## Dependencies ##

You'll need the following in your classpath along with joid.jar.

  * commons-logging-1.X.jar
  * tsik.jar

## web.xml ##

Add the servlet from above to your web.xml:

```
        <servlet>
		<servlet-name>loginServlet</servlet-name>
		<servlet-class>org.verisign.joid.server.OpenIdServlet</servlet-class>
		<init-param>
			<param-name>endPointUrl</param-name>
			<param-value>http://localhost:8080/joid/login</param-value>
			<description>Change this to your endpoint url.</description>
		</init-param>
		<init-param>
			<param-name>loginPage</param-name>
			<param-value>login.jsp</param-value>
			<description>Change this to your login page where the user enters their username and password and/or
				approves the authentication for the site.
			</description>
		</init-param>
                <init-param>
			<param-name>storeClassName</param-name>
			<param-value>org.verisign.joid.server.MemoryStore</param-value>
			<description>Specify the className for your Store implementation.
			</description>
		</init-param>
                <init-param>
			<param-name>userManagerClassName</param-name>
			<param-value>org.verisign.joid.server.MemoryUserManager</param-value>
			<description>Specify the className for your UserManager implementation.
			</description>
		</init-param>
	</servlet>

        <servlet-mapping>
		<servlet-name>loginServlet</servlet-name>
		<url-pattern>/login</url-pattern>
	</servlet-mapping>

```

Be sure to modify the init-params in the web.xml to the appropriate values.

## Login Page ##

You'll need some way for a user to login/authenticate themselves. There is a sample in /examples/server/login.jsp that simply asks the user to login and accept the Realm that is asking to authenticate.

## Running the Sample App ##

The sample app is both a consumer and a server. You can deploy it by dropping /out/joid.war into your TOMCAT\_HOME/webapps directory. Then surf to http://localhost:8080/joid/ to try it out.