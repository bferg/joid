The incoming OpenID request is handled by an _OpenID_ object, which has an associated _Store_and a _Crypto_ engine. Using these and a RequestFactory, a proper _Request_ is instantiated.

This request then processes using the store and crypto into a _Response), which is funneled back to the requestor._

Note that the flow can be reversed, with a _Response_ as input. This makes it possible to create relying parties as well as identity providers!


![http://joid.googlecode.com/svn/trunk/api/src/main/javadoc/flows.png](http://joid.googlecode.com/svn/trunk/api/src/main/javadoc/flows.png)


