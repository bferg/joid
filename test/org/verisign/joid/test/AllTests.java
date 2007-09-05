//
// (C) Copyright 2007 VeriSign, Inc.  All Rights Reserved.
//
// VeriSign, Inc. shall have no responsibility, financial or
// otherwise, for any consequences arising out of the use of
// this material. The program material is provided on an "AS IS"
// BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied.
//
// Distributed under an Apache License
// http://www.apache.org/licenses/LICENSE-2.0
//

package org.verisign.joid.test;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.verisign.joid.Association;
import org.verisign.joid.AssociationRequest;
import org.verisign.joid.AssociationResponse;
import org.verisign.joid.AuthenticationRequest;
import org.verisign.joid.AuthenticationResponse;
import org.verisign.joid.CheckAuthenticationRequest;
import org.verisign.joid.CheckAuthenticationResponse;
import org.verisign.joid.Crypto;
import org.verisign.joid.DiffieHellman;
import org.verisign.joid.MessageParser;
import org.verisign.joid.OpenId;
import org.verisign.joid.OpenIdException;
import org.verisign.joid.Request;
import org.verisign.joid.RequestFactory;
import org.verisign.joid.Response;
import org.verisign.joid.ResponseFactory;
import org.verisign.joid.ServerInfo;
import org.verisign.joid.SimpleRegistration;
import org.verisign.joid.Store;
import org.verisign.joid.StoreFactory;
import org.verisign.joid.server.AssociationImpl;
import org.verisign.joid.server.MemoryStore;

import java.math.BigInteger;
import java.net.URLEncoder;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;


public class AllTests extends TestCase
{
    private long defaultLifespan;

    public AllTests(String name) {super(name);}
    protected void setUp() throws Exception {
        super.setUp();
        defaultLifespan = MemoryStore.DEFAULT_LIFESPAN;
    }
    protected void tearDown() throws Exception {super.tearDown();}

    private static Crypto crypto = new Crypto();
    private static Store store = StoreFactory.getInstance(MemoryStore.class.getName());
    private static ServerInfo serverInfo = new ServerInfo("http://example.com",
							  store, crypto);

    public static Test suite() 
    {
        return new TestSuite(AllTests.class);
    }


    private static final SecureRandom srand;
    static {
        try {
            srand = SecureRandom.getInstance("SHA1PRNG");
        } catch (NoSuchAlgorithmException e) {
	    throw new RuntimeException("No SHA1 prng??");
        }
    }

    BigInteger p = DiffieHellman.DEFAULT_MODULUS;
    BigInteger g = DiffieHellman.DEFAULT_GENERATOR;

    private AssociationResponse associate(DiffieHellman dh)
	throws Exception
    {
	BigInteger publicKey = dh.getPublicKey();

	String s = "openid.mode=associate&openid.assoc_type=HMAC-SHA1"
	    +"&openid.session_type=DH-SHA1&openid.dh_consumer_public=";

	s += URLEncoder.encode(Crypto.convertToString(publicKey), "UTF-8");

	Request req = RequestFactory.parse(s);
	assertTrue(req instanceof AssociationRequest);
	Response resp = req.processUsing(serverInfo);
	assertTrue(resp instanceof AssociationResponse);
	s = resp.toUrlString();

	Response resp2 = ResponseFactory.parse(s);
	assertTrue(resp2 instanceof AssociationResponse);
	AssociationResponse ar = (AssociationResponse) resp;
	return ar;
    }

    private AssociationResponse associate256(DiffieHellman dh)
	throws Exception
    {
	BigInteger publicKey = dh.getPublicKey();

	String s = "openid.mode=associate&openid.assoc_type=HMAC-SHA256"
	    +"&openid.session_type=DH-SHA1&openid.dh_consumer_public=";

	s += URLEncoder.encode(Crypto.convertToString(publicKey), "UTF-8");

	Request req = RequestFactory.parse(s);
	assertTrue(req instanceof AssociationRequest);

	Response resp = req.processUsing(serverInfo);
	assertTrue(resp instanceof AssociationResponse);
	AssociationResponse foo = (AssociationResponse) resp;
	assertTrue(foo.getSessionType(),
		   "DH-SHA256".equals(foo.getSessionType()));
	assertTrue("HMAC-SHA256".equals(foo.getAssociationType()));
	s = resp.toUrlString();

	Response resp2 = ResponseFactory.parse(s);
	assertTrue(resp2 instanceof AssociationResponse);
	AssociationResponse ar = (AssociationResponse) resp;
	return ar;
    }

    
    public void testUrlToMap() throws Exception
    {
        String testStr = "path?foo=bar&baz=qux";
        Map map = MessageParser.urlEncodedToMap(testStr);
        assertTrue(map.size() == 2);
        assertTrue(((String)map.get("foo")).equals("bar"));
        assertTrue(((String)map.get("baz")).equals("qux"));
        testStr = "path?foo=bar;baz=qux";
        map = MessageParser.urlEncodedToMap(testStr);
        assertTrue(map.size() == 2);
        assertTrue(((String)map.get("foo")).equals("bar"));
        assertTrue(((String)map.get("baz")).equals("qux"));
    }


    public void testAssociationLifeLength() throws Exception
    {
	Association a = new AssociationImpl();
	a.setIssuedDate(new Date());
	a.setLifetime(new Long(1));
	assertFalse(a.hasExpired());
	Thread.sleep(1200);
	assertTrue(a.hasExpired());
    }

    public void testGetSharedSecret()
    {
        for (int i = 0; i < 3; i++) {
            DiffieHellman dh1 = new DiffieHellman(p,g);
            DiffieHellman dh2 = new DiffieHellman(p,g);

            BigInteger secret1 = dh1.getSharedSecret(dh2.getPublicKey());
            BigInteger secret2 = dh2.getSharedSecret(dh1.getPublicKey());

            assertEquals(secret1, secret2);
        }
    }
    
    public void test2() throws Exception
    {
	String s = Utils.readFileAsString("2.txt");

	Request req = RequestFactory.parse(s);
	assertTrue(req instanceof AssociationRequest);
	Response resp = req.processUsing(serverInfo);
	assertTrue(resp instanceof AssociationResponse);

	s = resp.toUrlString();

	Response resp2 = ResponseFactory.parse(s);
	assertTrue(resp2 instanceof AssociationResponse);
	AssociationResponse ar = (AssociationResponse) resp2;

	assertTrue(ar.getSessionType(),"DH-SHA1".equals(ar.getSessionType()));
	assertTrue("HMAC-SHA1".equals(ar.getAssociationType()));
	assertTrue(defaultLifespan == ar.getExpiresIn());
	assertTrue(null == ar.getMacKey());
	assertTrue(null != ar.getEncryptedMacKey());
	assertTrue(null != ar.getDhServerPublic());
	assertTrue(null == ar.getErrorCode());
    }

    public void test2b() throws Exception
    {
	String s = Utils.readFileAsString("2.txt");

	OpenId openId = new OpenId(serverInfo);
	assertTrue(openId.isAssociationRequest(s));
	assertFalse(openId.isAuthenticationRequest(s));
    }

    // Test no encryption 1.1 association request
    public void testAssocNoEncryption() throws Exception
    {
	String s = Utils.readFileAsString("5.txt");

	Request req = RequestFactory.parse(s);
	assertTrue(req instanceof AssociationRequest);
	Response resp = req.processUsing(serverInfo);
	assertTrue(resp instanceof AssociationResponse);

	s = resp.toUrlString();

	Response resp2 = ResponseFactory.parse(s);
	assertTrue(resp2 instanceof AssociationResponse);
	AssociationResponse ar = (AssociationResponse) resp2;

	assertTrue(null == ar.getSessionType());
	assertTrue("HMAC-SHA1".equals(ar.getAssociationType()));
	assertTrue(defaultLifespan == ar.getExpiresIn());
	assertTrue(null != ar.getMacKey());
	assertTrue(null == ar.getEncryptedMacKey());
	assertTrue(null == ar.getDhServerPublic());
	assertTrue(null == ar.getErrorCode());
    }

    public void testMarshall() throws Exception
    {
	DiffieHellman dh = new DiffieHellman(p, g);
	BigInteger privateKey = dh.getPrivateKey();
	BigInteger publicKey = dh.getPublicKey();
	String s = Crypto.convertToString(privateKey);
	BigInteger b = Crypto.convertToBigIntegerFromString(s);
	assertEquals(privateKey, b);
	s = Crypto.convertToString(publicKey);
	b = Crypto.convertToBigIntegerFromString(s);
	assertEquals(publicKey, b);
    }

    public void testSchtuffTrustRoot() throws Exception
    {
	String s = "openid.identity=http%3A%2F%2Fhans.beta.abtain.com%2F"
	    +"&openid.mode=checkid_setup"
	    +"&openid.return_to=http%3A%2F%2Fwww.schtuff.com%2F%3Faction%3Dope"
	    +"nid_return%26dest%3D%26stay_logged_in%3DFalse%26response_no"
	    +"nce%3D2006-12-"
	    +"06T04%253A54%253A51ZQvGYW3"
	    +"&openid.trust_root=http%3A%2F%2F%2A.schtuff.com%2F";

	Request req = RequestFactory.parse(s);
	assertTrue(req instanceof AuthenticationRequest);
    }

    public void testOpenIdNetDemoTrustRoot() throws Exception
    {
	String s = "openid.mode=checkid_setup&"
	    +"openid.identity=http://hans.beta.abtain.com/&"
	    +"openid.return_to=http://openid.net/demo/helpe"
	    +"r.bml%3Fstyle%3Dclassic%26oic.time%3D11654216"
	    +"99-368eacd1483709faab32&"
	    +"openid.trust_root=http://%2A.openid.net/demo/&"
	    +"openid.assoc_handle=1c431e80-8545-11db-9ff5-1"
	    +"55b0e692653";
	Request req = RequestFactory.parse(s);
	assertTrue(req instanceof AuthenticationRequest);
    }

    public void testTrustRoot() throws Exception
    {
	String base = "openid.mode=checkid_setup&openid.identity="
	    +"http://my.identity&openid.return_to=http://a.example.com";

	String foo = base + "&openid.trust_root=http://*.example.com";
	Request req = RequestFactory.parse(foo);
	assertTrue(req instanceof AuthenticationRequest);

	foo = base + "&openid.trust_root=http://www.example.com";
	try {
	    RequestFactory.parse(foo);
	    fail("Should have thrown");
	} catch (OpenIdException e){}


	// Trust root     Return to
	// ----------     ---------
	// /a/b/c     =>  /a/b/c/d    ==> ok
	// /a/b/c     =>  /a/b        ==> not ok
	// /a/b/c     =>  /a/b/b      ==> not ok
	//

	base = "openid.mode=checkid_setup&openid.identity="
	    +"http://my.identity&openid.trust_root=http://example.com/a/b/c";

	foo = base + "&openid.return_to=http://example.com/a/b/c/d";
	req = RequestFactory.parse(foo);
	assertTrue(req instanceof AuthenticationRequest);

	foo = base + "&openid.return_to=http://example.com/a/b";
	try {
	    RequestFactory.parse(foo);
	    fail("Should have thrown");
	} catch (OpenIdException e){}

	foo = base + "&openid.return_to=http://example.com/a/b/b";
	try {
	    RequestFactory.parse(foo);
	    fail("Should have thrown");
	} catch (OpenIdException e){}

    }

    public void test3() throws Exception
    {
	DiffieHellman dh = new DiffieHellman(p, g);
	AssociationResponse ar = associate(dh);
	assertFalse(ar.isVersion2());
	BigInteger privateKey = dh.getPrivateKey();
	BigInteger publicKey = dh.getPublicKey();

	assertTrue(ar.getSessionType(),"DH-SHA1".equals(ar.getSessionType()));
	assertTrue("HMAC-SHA1".equals(ar.getAssociationType()));
	assertTrue(defaultLifespan == ar.getExpiresIn());
	assertTrue(null == ar.getErrorCode());
	assertTrue(null == ar.getMacKey());

	byte[] encKey = ar.getEncryptedMacKey();
	assertTrue(null != encKey);

	BigInteger serverPublic = ar.getDhServerPublic();
	assertTrue(null != serverPublic);

	byte[] clearKey = dh.xorSecret(serverPublic, encKey);

	// authenticate
	String s = Utils.readFileAsString("3bv1.txt");
	s += "?openid.assoc_handle="
	    + URLEncoder.encode(ar.getAssociationHandle(), "UTF-8");

	Request req = RequestFactory.parse(s);
	assertTrue(req instanceof AuthenticationRequest);
	assertFalse(req.isVersion2());
	Response resp = req.processUsing(serverInfo);
	assertTrue(resp instanceof AuthenticationResponse);
	assertFalse(resp.isVersion2());

	s = resp.toUrlString();

	Response resp2 = ResponseFactory.parse(s);
	assertTrue(resp2 instanceof AuthenticationResponse);
	AuthenticationResponse authr = (AuthenticationResponse) resp2;
	assertFalse(authr.isVersion2());
    assertTrue(null == authr.getUrlEndPoint());
    
	String sigList = authr.getSignedList();
	assertTrue(sigList != null);
	String signature = authr.getSignature();
	assertTrue(signature != null);

	String reSigned = authr.sign("HMAC-SHA1", clearKey, sigList);
	assertEquals(reSigned, signature);


	// check that we can authenticate the signature
	//
	Map map = authr.toMap();
	CheckAuthenticationRequest carq
	    = new CheckAuthenticationRequest(map, "check_authentication");
	assertFalse(carq.isVersion2());

	resp = carq.processUsing(serverInfo);
	assertFalse(resp.isVersion2());
	assertTrue(resp instanceof CheckAuthenticationResponse);
	CheckAuthenticationResponse carp = (CheckAuthenticationResponse) resp;
	assertTrue(carp.isValid());
    }

    public void test3_badsig() throws Exception
    {
	DiffieHellman dh = new DiffieHellman(p, g);
	AssociationResponse ar = associate(dh);
	assertFalse(ar.isVersion2());
	BigInteger privateKey = dh.getPrivateKey();
	BigInteger publicKey = dh.getPublicKey();

	assertTrue(ar.getSessionType(),"DH-SHA1".equals(ar.getSessionType()));
	assertTrue("HMAC-SHA1".equals(ar.getAssociationType()));
	assertTrue(defaultLifespan == ar.getExpiresIn());
	assertTrue(null == ar.getErrorCode());
	assertTrue(null == ar.getMacKey());

	byte[] encKey = ar.getEncryptedMacKey();
	assertTrue(null != encKey);

	BigInteger serverPublic = ar.getDhServerPublic();
	assertTrue(null != serverPublic);

	byte[] clearKey = dh.xorSecret(serverPublic, encKey);

	// authenticate
	String s = Utils.readFileAsString("3bv1.txt");
	s += "?openid.assoc_handle="
	    + URLEncoder.encode(ar.getAssociationHandle(), "UTF-8");

	Request req = RequestFactory.parse(s);
	assertTrue(req instanceof AuthenticationRequest);
	assertFalse(req.isVersion2());
	Response resp = req.processUsing(serverInfo);
	assertTrue(resp instanceof AuthenticationResponse);
	assertFalse(resp.isVersion2());

	s = resp.toUrlString();

	Response resp2 = ResponseFactory.parse(s);
	assertTrue(resp2 instanceof AuthenticationResponse);
	AuthenticationResponse authr = (AuthenticationResponse) resp2;
	assertFalse(authr.isVersion2());

	String sigList = authr.getSignedList();
	assertTrue(sigList != null);
	String signature = authr.getSignature();
	assertTrue(signature != null);

	String reSigned = authr.sign("HMAC-SHA1", clearKey, sigList);
	assertEquals(reSigned, signature);


	// check that the wrong signature doesn't authenticate
	//
	Map map = authr.toMap();
	map.put("openid.sig", "pO+52CAFEBABEuu0lVRivEeu2Zw=");
	CheckAuthenticationRequest carq 
	    = new CheckAuthenticationRequest(map, "check_authentication");

	resp = carq.processUsing(serverInfo);
	assertFalse(resp.isVersion2());
	assertTrue(resp instanceof CheckAuthenticationResponse);
	CheckAuthenticationResponse carp = (CheckAuthenticationResponse) resp;
	assertFalse(carp.isValid());
    }


    public void testSreg() throws Exception
    {
	DiffieHellman dh = new DiffieHellman(p, g);
	AssociationResponse ar = associate(dh);
	BigInteger privateKey = dh.getPrivateKey();
	BigInteger publicKey = dh.getPublicKey();

	assertTrue(ar.getSessionType(),"DH-SHA1".equals(ar.getSessionType()));
	assertTrue("HMAC-SHA1".equals(ar.getAssociationType()));
	assertTrue(defaultLifespan == ar.getExpiresIn());
	assertTrue(null == ar.getErrorCode());
	assertTrue(null == ar.getMacKey());

	byte[] encKey = ar.getEncryptedMacKey();
	assertTrue(null != encKey);

	BigInteger serverPublic = ar.getDhServerPublic();
	assertTrue(null != serverPublic);

	byte[] clearKey = dh.xorSecret(serverPublic, encKey);


	// authenticate
	String s = Utils.readFileAsString("sreg.txt");
	s += "?openid.assoc_handle="
	    + URLEncoder.encode(ar.getAssociationHandle(), "UTF-8");

	Request req = RequestFactory.parse(s);
	assertTrue(req.isVersion2());
	assertTrue(req instanceof AuthenticationRequest);
	SimpleRegistration sreg = ((AuthenticationRequest) req)
	    .getSimpleRegistration();
	Set set = sreg.getRequired();
	Map supplied = new HashMap();
	for (Iterator iter = set.iterator(); iter.hasNext();){
	    s = (String) iter.next();
	    supplied.put(s, "blahblah");
	} 
	sreg = new SimpleRegistration(set, Collections.EMPTY_SET, supplied, "");
	((AuthenticationRequest) req).setSimpleRegistration(sreg);

	Response resp = req.processUsing(serverInfo);
	assertTrue(resp instanceof AuthenticationResponse);
	assertTrue(resp.isVersion2());

	s = resp.toUrlString();

	Response resp2 = ResponseFactory.parse(s);
	assertTrue(resp2 instanceof AuthenticationResponse);
	AuthenticationResponse authr = (AuthenticationResponse) resp2;
	assertTrue(authr.isVersion2());

	String sigList = authr.getSignedList();
	assertTrue(sigList != null);
	String signature = authr.getSignature();
	assertTrue(signature != null);

	String reSigned = authr.sign("HMAC-SHA1", clearKey, sigList);
	assertEquals(reSigned, signature);

	// check that we can authenticate the signaure
	//
	Map map = authr.toMap();
	CheckAuthenticationRequest carq 
	    = new CheckAuthenticationRequest(map, "check_authentication");

    // Check for sreg namespace
    if (resp.isVersion2()) {
        assertEquals((String)map.get("openid.ns.sreg"), 
                     SimpleRegistration.OPENID_SREG_NAMESPACE);
    }

	resp = carq.processUsing(serverInfo);
	assertTrue(resp.isVersion2());
	assertTrue(resp instanceof CheckAuthenticationResponse);
	CheckAuthenticationResponse carp = (CheckAuthenticationResponse) resp;
	assertTrue(carp.isValid());
    }

    String v2 = "http://specs.openid.net/auth/2.0";

    public void testVersion2() throws Exception
    {
	String s = Utils.readFileAsString("2.txt");
	s += "openid.ns="+v2;

	Request req = RequestFactory.parse(s);
	assertTrue(req instanceof AssociationRequest);
	Response resp = req.processUsing(serverInfo);
	assertTrue(resp instanceof AssociationResponse);
	assertTrue(resp.isVersion2());

	s = resp.toUrlString();
	Response resp2 = ResponseFactory.parse(s);
	assertTrue(resp2.isVersion2());
	assertTrue(resp2 instanceof AssociationResponse);

	AssociationResponse ar = (AssociationResponse) resp2;

	assertTrue(ar.getSessionType(),"DH-SHA1".equals(ar.getSessionType()));
	assertTrue("HMAC-SHA1".equals(ar.getAssociationType()));
	assertTrue(defaultLifespan == ar.getExpiresIn());
	assertTrue(null == ar.getMacKey());
	assertTrue(null != ar.getEncryptedMacKey());
	assertTrue(null != ar.getDhServerPublic());
	assertTrue(null == ar.getErrorCode());
	assertTrue(v2.equals(ar.getNamespace()));
    }


    public void test3version2() throws Exception
    {
	DiffieHellman dh = new DiffieHellman(p, g);
	AssociationResponse ar = associate(dh);
	BigInteger privateKey = dh.getPrivateKey();
	BigInteger publicKey = dh.getPublicKey();

	assertTrue(ar.getSessionType(),"DH-SHA1".equals(ar.getSessionType()));
	assertTrue("HMAC-SHA1".equals(ar.getAssociationType()));
	assertTrue(defaultLifespan == ar.getExpiresIn());
	assertTrue(null == ar.getErrorCode());
	assertTrue(null == ar.getMacKey());

	byte[] encKey = ar.getEncryptedMacKey();
	assertTrue(null != encKey);

	BigInteger serverPublic = ar.getDhServerPublic();
	assertTrue(null != serverPublic);

	byte[] clearKey = dh.xorSecret(serverPublic, encKey);


	// authenticate
	String s = Utils.readFileAsString("3b.txt");
	s += "?openid.ns="+v2
	    + "?openid.assoc_handle="
	    + URLEncoder.encode(ar.getAssociationHandle(), "UTF-8");

	Request req = RequestFactory.parse(s);

	assertTrue(req instanceof AuthenticationRequest);
	assertTrue(req.isVersion2());
	assertTrue(((AuthenticationRequest) req).getClaimedIdentity() == null);
	Response resp = req.processUsing(serverInfo);

	assertTrue(resp instanceof AuthenticationResponse);
	assertTrue(resp.isVersion2());

	s = resp.toUrlString();

	Response resp2 = ResponseFactory.parse(s);
	assertTrue(resp2 instanceof AuthenticationResponse);
	assertTrue(resp2.isVersion2());
	AuthenticationResponse authr = (AuthenticationResponse) resp;

	String sigList = authr.getSignedList();
	assertTrue(sigList != null);
	assertTrue(sigList.indexOf("claimed_id") == -1);
	String signature = authr.getSignature();
	assertTrue(signature != null);
	String namespace = authr.getNamespace();
	assertTrue(v2.equals(namespace));

	String reSigned = authr.sign("HMAC-SHA1", clearKey, sigList);
	assertEquals(reSigned, signature);


	// check that we can authenticate the signaure
	//
	Map map = authr.toMap();
	CheckAuthenticationRequest carq 
	    = new CheckAuthenticationRequest(map, "check_authentication");

	resp = carq.processUsing(serverInfo);
	assertTrue(resp.isVersion2());
	assertTrue(resp instanceof CheckAuthenticationResponse);
	CheckAuthenticationResponse carp = (CheckAuthenticationResponse) resp;
	assertTrue(carp.isValid());
    }

    public void test3version2_badsig() throws Exception
    {
	DiffieHellman dh = new DiffieHellman(p, g);
	AssociationResponse ar = associate(dh);
	BigInteger privateKey = dh.getPrivateKey();
	BigInteger publicKey = dh.getPublicKey();

	assertTrue(ar.getSessionType(),"DH-SHA1".equals(ar.getSessionType()));
	assertTrue("HMAC-SHA1".equals(ar.getAssociationType()));
	assertTrue(defaultLifespan == ar.getExpiresIn());
	assertTrue(null == ar.getErrorCode());
	assertTrue(null == ar.getMacKey());

	byte[] encKey = ar.getEncryptedMacKey();
	assertTrue(null != encKey);

	BigInteger serverPublic = ar.getDhServerPublic();
	assertTrue(null != serverPublic);

	byte[] clearKey = dh.xorSecret(serverPublic, encKey);


	// authenticate
	String s = Utils.readFileAsString("3b.txt");
	s += "?openid.ns="+v2
	    + "?openid.assoc_handle="
	    + URLEncoder.encode(ar.getAssociationHandle(), "UTF-8");

	Request req = RequestFactory.parse(s);

	assertTrue(req instanceof AuthenticationRequest);
	assertTrue(req.isVersion2());
	assertTrue(((AuthenticationRequest) req).getClaimedIdentity() == null);
	Response resp = req.processUsing(serverInfo);

	assertTrue(resp instanceof AuthenticationResponse);
	assertTrue(resp.isVersion2());

	s = resp.toUrlString();

	Response resp2 = ResponseFactory.parse(s);
	assertTrue(resp2 instanceof AuthenticationResponse);
	assertTrue(resp2.isVersion2());
	AuthenticationResponse authr = (AuthenticationResponse) resp;
    assertTrue(null != authr.getUrlEndPoint());

	String sigList = authr.getSignedList();
	assertTrue(sigList != null);
	assertTrue(sigList.indexOf("claimed_id") == -1);
	String signature = authr.getSignature();
	assertTrue(signature != null);
	String namespace = authr.getNamespace();
	assertTrue(v2.equals(namespace));

	String reSigned = authr.sign("HMAC-SHA1", clearKey, sigList);
	assertEquals(reSigned, signature);


	// Check that the wrong signature doesn't authenticate
	//
	Map map = authr.toMap();
	map.put("openid.sig", "pO+52CAFEBABEuu0lVRivEeu2Zw=");
	CheckAuthenticationRequest carq 
	    = new CheckAuthenticationRequest(map, "check_authentication");
	assertTrue(carq.isVersion2());

	resp = carq.processUsing(serverInfo);
	assertTrue(resp instanceof CheckAuthenticationResponse);
	CheckAuthenticationResponse carp = (CheckAuthenticationResponse) resp;
	assertFalse(carp.isValid());
    }


    public void test3_claimedid_noncecheck() throws Exception
    {
	DiffieHellman dh = new DiffieHellman(p, g);
	AssociationResponse ar = associate(dh);
	BigInteger privateKey = dh.getPrivateKey();
	BigInteger publicKey = dh.getPublicKey();

	assertTrue(ar.getSessionType(),"DH-SHA1".equals(ar.getSessionType()));
	assertTrue("HMAC-SHA1".equals(ar.getAssociationType()));
	assertTrue(defaultLifespan == ar.getExpiresIn());
	assertTrue(null == ar.getErrorCode());
	assertTrue(null == ar.getMacKey());

	byte[] encKey = ar.getEncryptedMacKey();
	assertTrue(null != encKey);

	BigInteger serverPublic = ar.getDhServerPublic();
	assertTrue(null != serverPublic);

	byte[] clearKey = dh.xorSecret(serverPublic, encKey);


	// authenticate
	String s = Utils.readFileAsString("3c.txt");
	s += "?openid.ns="+v2
	    + "?openid.assoc_handle="
	    + URLEncoder.encode(ar.getAssociationHandle(), "UTF-8");

	Request req = RequestFactory.parse(s);

	assertTrue(req instanceof AuthenticationRequest);
	assertTrue(req.isVersion2());
	assertTrue(((AuthenticationRequest) req).getClaimedIdentity() !=null);
	Response resp = req.processUsing(serverInfo);

	assertTrue(resp instanceof AuthenticationResponse);
	assertTrue(resp.isVersion2());

	s = resp.toUrlString();

	Response resp2 = ResponseFactory.parse(s);
	assertTrue(resp2 instanceof AuthenticationResponse);
	assertTrue(resp2.isVersion2());
	AuthenticationResponse authr = (AuthenticationResponse) resp;

	String sigList = authr.getSignedList();
	assertTrue(sigList != null);
	assertTrue(sigList.indexOf("claimed_id") != -1);
	String signature = authr.getSignature();
	assertTrue(signature != null);
	String namespace = authr.getNamespace();
	assertTrue(v2.equals(namespace));

	String reSigned = authr.sign("HMAC-SHA1", clearKey, sigList);
	assertEquals(reSigned, signature);


	// check that we can authenticate the signaure
	//
	Map map = authr.toMap();
	CheckAuthenticationRequest carq 
	    = new CheckAuthenticationRequest(map, "check_authentication");

	resp = carq.processUsing(serverInfo);
	assertTrue(resp.isVersion2());
	assertTrue(resp instanceof CheckAuthenticationResponse);
	CheckAuthenticationResponse carp = (CheckAuthenticationResponse) resp;
	assertTrue(carp.isValid());


	// A 2nd check auth should fail (nonce check)
	//
	try {
	    resp = carq.processUsing(serverInfo);
	    assertTrue(false); 
	} catch (OpenIdException e) {
	    // should throw
	}
    }

    public void testEndsWithEquals() throws Exception
    {
	String s = "openid.assoc_handle=%7BHMAC-SHA1%7D%7B44e56"
	    +"f1d%7D%7BqrHn2Q%3D%3D%7D&openid.identity=http%3A%"
	    +"2F%2Fmisja.pip.verisignlabs.com%2F&openid.mode=ch"
	    +"eckid_setup"
	    +"&openid.return_to=http%3A%2F%2Fradagast.biz%2Felg"
	    +"g2%2Fmod%2Fopenid_client%2Freturn.php%3Fresponse_"
	    +"nonce%3DR"
	    +"qyqPiwW&openid.sreg.optional=email%2Cfullname"
	    +"&openid.trust_root=";

	try {
	    // no longer throws an exception because an unspecified
	    // trust_root is assumed to be the return_to url
	    Request req = RequestFactory.parse(s);
	} catch (OpenIdException unexpected){
        assertTrue(false);
	}
    }

    public void testEmptyIdentity() throws Exception
    {
	String s = "openid.return_to=http%3A%2F%2Ftest.vladlife.c"
	    +"om%2Ffivestores%2Fclass.openid.php&openid.cancel_to"
	    +"=&openid.mode=checkid_setup&openid.identity=&openid"
	    +".trust_root=http%3A%2F%2Ftest.vladlife.com&";
	try {
	    Request req = RequestFactory.parse(s);
	    Response resp = req.processUsing(serverInfo);
	    assertTrue(false);
	} catch (OpenIdException expected){
	}
    }
    
    public void testMissingDhPublic() throws Exception
    {
	
	String s = "openid.mode=associate"
	    +"&openid.session_type=DH-SHA1";
	
	try {
	    Request req = RequestFactory.parse(s);
	    assertTrue(false);
	} catch (OpenIdException expected){

	}
    }

    /** Tests that 'realm' is treated just like 'trust_root' */
    public void testRealm() throws Exception
    {
	DiffieHellman dh = new DiffieHellman(p, g);
	AssociationResponse ar = associate(dh);

	String s = "openid.return_to=http%3A%2F%2Fexample.com&ope"
	    +"nid.realm=http%3A%2F%2Fexample.com&openid.ns=http%"
	    +"3A%2F%2Fspecs.openid.net%2Fauth%2F2.0&openid.claimed_id"
	    +"=http%3A%2F%2Falice.example.com&openid.mode=checkid"
	    +"_setup&openid.identity=http%3A%2F%2Fexample.com&ope"
	    +"nid.assoc_handle="+ar.getAssociationHandle();

	Request req = RequestFactory.parse(s);
	Response resp = req.processUsing(serverInfo);
    }

    /** Tests that trailing slashes on URLs are *not* canonicalized.
     * That is: http://example.com is not equals to http://example.com/
     */
    public void testTrailing() throws Exception
    {
	String s = "openid.return_to=http%3A%2F%2Fexample.com&ope"
	    +"nid.realm=http%3A%2F%2Fexample.com/&openid.ns=http%"
	    +"3A%2F%2Fspecs.openid.net%2Fauth%2F2.0&openid.claimed_id"
	    +"=http%3A%2F%2Falice.example.com&openid.mode=checkid"
	    +"_setup&openid.identity=http%3A%2F%2Fexample.com&ope"
	    +"nid.assoc_handle=1b184cb";

	try {
	    Request req = RequestFactory.parse(s);
	    Response resp = req.processUsing(serverInfo);
	    assertTrue(false);
	} catch (OpenIdException expected){
	}
    }

    /** Tests that identity can change.
     */
    public void testChangeId() throws Exception
    {
	String s = "openid.identity=http%3A%2F%2Fhans.beta.abtain.com%2F"
	    +"&openid.mode=checkid_setup"
	    +"&openid.return_to=http%3A%2F%2Fwww.schtuff.com%2F%3Faction%3Dope"
	    +"nid_return%26dest%3D%26stay_logged_in%3DFalse%26response_no"
	    +"nce%3D2006-12-"
	    +"06T04%253A54%253A51ZQvGYW3"
	    +"&openid.trust_root=http%3A%2F%2F%2A.schtuff.com%2F"
	    +"&openid.assoc_handle=ahandle";

	Request req = RequestFactory.parse(s);
	assertTrue(req instanceof AuthenticationRequest);
	AuthenticationRequest ar = (AuthenticationRequest) req;
	assertFalse(ar.isIdentifierSelect());
	ar.setIdentity("http://newidentity.example.com");
	String x = ar.toUrlString();
	assertFalse(s.equals(x));
    }

    /** Tests that identity_select works.
     */
    public void testIdentitySelect() throws Exception
    {
	String s = "openid.identity="
	    +"http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select"
	    +"&openid.mode=checkid_setup"
	    +"&openid.return_to=http%3A%2F%2Fwww.schtuff.com%2F%3Faction%3Dope"
	    +"nid_return%26dest%3D%26stay_logged_in%3DFalse%26response_no"
	    +"nce%3D2006-12-"
	    +"06T04%253A54%253A51ZQvGYW3"
	    +"&openid.trust_root=http%3A%2F%2F%2A.schtuff.com%2F"
	    +"&openid.assoc_handle=ahandle";

	Request req = RequestFactory.parse(s);
	assertTrue(req instanceof AuthenticationRequest);
	AuthenticationRequest ar = (AuthenticationRequest) req;
	assertTrue(ar.isIdentifierSelect());
    }

    /** Tests that extensions work.
     */
    public void testExtensions() throws Exception
    {
	String s = "openid.identity="
	    +"http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select"
	    +"&openid.mode=checkid_setup"
	    +"&openid.return_to=http%3A%2F%2Fwww.schtuff.com%2F%3Faction%3Dope"
	    +"nid_return%26dest%3D%26stay_logged_in%3DFalse%26response_no"
	    +"nce%3D2006-12-"
	    +"06T04%253A54%253A51ZQvGYW3"
	    +"&openid.trust_root=http%3A%2F%2F%2A.schtuff.com%2F"
	    +"&openid.assoc_handle=ahandle"
	    +"&openid.ns.sig=http%3A%2F%2Fcommented.org"
	    +"&openid.foo=happiness%20is%20a%20warm%20bun"
	    +"&openid.glass.bunion=rocky%20sassoon%20gluebird%20foolia";

	try {
	    Request req = RequestFactory.parse(s);
	    assertTrue(false);
	} catch (OpenIdException e) {
	    // expected: ns.sig cannot be redefined
	}
    }

    /** Tests that extensions work.
     */
    public void testExtensions2() throws Exception
    {
	String s = "openid.identity="
	    +"http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select"
	    +"&openid.mode=checkid_setup"
	    +"&openid.return_to=http%3A%2F%2Fwww.schtuff.com%2F%3Faction%3Dope"
	    +"nid_return%26dest%3D%26stay_logged_in%3DFalse%26response_no"
	    +"nce%3D2006-12-"
	    +"06T04%253A54%253A51ZQvGYW3"
	    +"&openid.trust_root=http%3A%2F%2F%2A.schtuff.com%2F"
	    +"&openid.ns.foo=http%3A%2F%2Fcommented.org"
	    +"&openid.foo=trycke%20e%20for%20mycke"
	    +"&openid.foo.bar=jaha%20vadda%20nu%20da";

	Request req = RequestFactory.parse(s);
	assertTrue(req instanceof AuthenticationRequest);
	AuthenticationRequest ar = (AuthenticationRequest) req;
	assertTrue(ar.isIdentifierSelect());

	Map map = ar.getExtensions();
	assertTrue(map.containsKey("ns.foo"));
	assertTrue(map.containsKey("foo"));
	assertTrue(map.containsKey("foo.bar"));
    }

}
