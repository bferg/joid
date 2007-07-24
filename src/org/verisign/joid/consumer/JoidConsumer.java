package org.verisign.joid.consumer;

import org.verisign.joid.*;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

/**
 * This is the main class for consumers to use.
 *
 * It performs the following operations given an OpenID user identifier.
 * - Finds the OpenId Server
 * - Associates with the server if it hasn't done so already or if the association has expired
 * - Provides url to the server an application to redirect to.
 *
 * ... some time later ...
 *
 * - Takes a request from an OpenId server after user has authenticated
 * - Verifies server signature and our signatures match to authenticate
 * - Returns the user's identifier if ok
 *
 *
 * User: treeder
 * Date: Jun 27, 2007
 * Time: 11:52:40 AM
 */
public class JoidConsumer {


	private Map/*<String, Properties>*/ propSingleton;
	private Map/*<String, String>*/ handleToIdServer;
	private Discoverer discoverer = new Discoverer();

	private synchronized Properties getProps(String idserver) {
		if (propSingleton == null) {
			propSingleton = new HashMap();
			handleToIdServer = new HashMap();
		}
		Properties props = (Properties) propSingleton.get(idserver);
		if(props == null){
			try {
				props = associate(idserver);
				propSingleton.put(idserver, props);
				handleToIdServer.put(props.getProperty("handle"), idserver);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		return props;
	}

	private Properties getPropsByHandle(String associationHandle) throws OpenIdException {
		String idServer = (String) handleToIdServer.get(associationHandle);
		System.out.println("got idserver for handle: " + associationHandle + " - " + idServer);
		if(idServer == null){
			throw new OpenIdException("handle for server not found!");
		}
		return getProps(idServer);
	}

	/**
	 * To associate with an openid server
	 *
	 * @param idserver server url
	 * @return
	 * @throws java.io.IOException
	 * @throws org.verisign.joid.OpenIdException
	 */
	public Properties associate(String idserver) throws IOException, OpenIdException {
		DiffieHellman dh = DiffieHellman.getDefault();
		Crypto crypto = new Crypto();
		crypto.setDiffieHellman(dh);

		AssociationRequest ar = AssociationRequest.create(crypto);

		Response response = Util.send(ar, idserver);
		System.out.println("Response=" + response + "\n");

		AssociationResponse asr = (AssociationResponse) response;

		Properties props = new Properties();
		props.setProperty("handle", asr.getAssociationHandle());
		props.setProperty("publicKey",
				Crypto.convertToString(asr.getDhServerPublic()));
		props.setProperty("encryptedKey",
				Crypto.convertToString(asr.getEncryptedMacKey()));

		BigInteger privateKey = dh.getPrivateKey();
		props.setProperty("privateKey", Crypto.convertToString(privateKey));
		props.setProperty("modulus",
				Crypto.convertToString(DiffieHellman.DEFAULT_MODULUS));

		props.setProperty("_dest", idserver);

		/*
	  Crypto crypto = new Crypto();
	  dh = DiffieHellman.recreate(privateKey, p);
	 crypto.setDiffieHellman(dh);
	  byte[] clearKey	= crypto.decryptSecret(asr.getDhServerPublic(),
							 asr.getEncryptedMacKey());
	 System.out.println("Clear key: "+Crypto.convertToString(clearKey));
	 */
		return props;
	}

	public String getAuthUrl(String identity, String returnTo, String trustRoot) throws OpenIdException {

		// find id server
		ServerAndDelegate idserver = null;
		try {
			idserver = discoverer.findIdServer(identity);
		} catch (IOException e) {
			e.printStackTrace();
			throw new OpenIdException("Could not get OpenId server from identifier.", e);
		}

		Properties p = getProps(idserver.getServer());
		String handle = p.getProperty("handle");
		String dest = p.getProperty("_dest");

		// todo: use delegate here, replace identity?

		AuthenticationRequest ar = AuthenticationRequest.create(identity, returnTo, trustRoot, handle);

		System.out.println("urlString=" + ar.toUrlString());

		return idserver.getServer() + "?" + ar.toUrlString();
	}



	public String authenticate(Map map)
			throws IOException, OpenIdException, NoSuchAlgorithmException {

		AuthenticationResponse response =
//				ResponseFactory.parse(responseString);
				new AuthenticationResponse(map);

		Properties p = getPropsByHandle(response.getAssociationHandle());

		AuthenticationResponse authr = (AuthenticationResponse) response;

		BigInteger privKey
				= Crypto.convertToBigIntegerFromString(p.getProperty("privateKey"));
		BigInteger modulus
				= Crypto.convertToBigIntegerFromString(p.getProperty("modulus"));
		BigInteger serverPublic
				= Crypto.convertToBigIntegerFromString(p.getProperty("publicKey"));
		byte[] encryptedKey
				= Crypto.convertToBytes(p.getProperty("encryptedKey"));

		DiffieHellman dh = DiffieHellman.recreate(privKey, modulus);
		Crypto crypto = new Crypto();
		crypto.setDiffieHellman(dh);
		byte[] clearKey = crypto.decryptSecret(serverPublic, encryptedKey);

		String signature = authr.getSignature();
		System.out.println("Server's signature: " + signature);

		String sigList = authr.getSignedList();
		String reSigned = authr.sign(clearKey, sigList);
		System.out.println("Our signature:      " + reSigned);
		String identity = (String) map.get("openid.identity");
		if (!signature.equals(reSigned)) {
			throw new AuthenticationException("OpenId tokens do not match! claimed identity: " + identity);
		}
		System.out.println("tokens match, identity is ok: " + identity);
		return identity;
	}


}
