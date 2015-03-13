## Introduction ##

To use JOID as a Consumer, there are basically two steps.

  1. Add OpenIdFilter to your web.xml
  1. Create an OpenID login form

## OpenIdFilter ##

Add the following to web.xml
```
        <filter>
		<filter-name>OpenIdFilter</filter-name>
		<filter-class>org.verisign.joid.consumer.OpenIdFilter</filter-class>
		<init-param>
			<param-name>saveInCookie</param-name>
			<param-value>true</param-value>
			<description>Optional. Will store the identity url in a cookie under "openid.identity" if set to true.</description>
		</init-param>
		<!--
		<init-param>
			<param-name>cookieDomain</param-name>
			<param-value>www.mydomain.com</param-value>
			<description>Optional. Domain to store cookie based on RFC 2109. Defaults to current context.</description>
		</init-param>
		-->
	</filter>
        <filter-mapping>
		<filter-name>OpenIdFilter</filter-name>
		<url-pattern>/*</url-pattern>
	</filter-mapping>
```

## OpenID Form ##

This form will accept a users OpenID URL identifier and upon submit, it redirects to the OpenID server identified by the URL and asks the user to accept the authentication request.

See here for example pages you can use and modify:
http://joid.googlecode.com/svn/trunk/examples/server/