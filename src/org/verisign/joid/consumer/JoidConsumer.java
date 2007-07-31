package org.verisign.joid.consumer;

import org.verisign.joid.*;
import org.apache.log4j.Logger;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

/**
 * This is the main class for consumers to use.
 * <p/>
 * It performs the following operations given an OpenID user identifier.
 * - Finds the OpenId Server
 * - Associates with the server if it hasn't done so already or if the
 * association has expired
 * - Provides url to the server an application to redirect to.
 * <p/>
 * ... some time later ...
 * <p/>
 * - Takes a request from an OpenId server after user has authenticated
 * - Verifies server signature and our signatures match to authenticate
 * - Returns the user's identifier if ok
 * <p/>
 * <p/>
 * User: treeder
 * Date: Jun 27, 2007
 * Time: 11:52:40 AM
 */
public class JoidConsumer {

    private static Logger log = Logger.getLogger(JoidConsumer.class);

    private Map/*<String, Properties>*/ propSingleton;
    private Map/*<String, String>*/ handleToIdServer;
    private Discoverer discoverer = new Discoverer();

    private synchronized Properties getProps(String idserver) {
        if (propSingleton == null) {
            propSingleton = new HashMap();
            handleToIdServer = new HashMap();
        }
        Properties props = (Properties) propSingleton.get(idserver);
        if (props == null) {
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

    private Properties getPropsByHandle(String associationHandle)
            throws OpenIdException {
        String idServer = (String) handleToIdServer.get(associationHandle);
        System.out.println("got idserver for handle: " + associationHandle +
                " - " + idServer);
        if (idServer == null) {
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
     *
     */
    public Properties associate(String idserver)
            throws IOException, OpenIdException {
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

    /**
     * This method is used by a relying party to create the url to redirect a
     * user to after entering their OpenId URL in a form.
     *
     * It will find the id server found at the OpenID url, associate with the
     * server if necessary and return an authentication request url.
     *
     * @param identity users OpenID url
     * @param returnTo the url to return to after user is finished with OpenId provider
     * @param trustRoot base url that the authentication should apply to
     * @return
     * @throws OpenIdException
     */
    public String getAuthUrl(String identity, String returnTo, String trustRoot)
            throws OpenIdException {

        // find id server
        ServerAndDelegate idserver = null;
        try {
            idserver = discoverer.findIdServer(identity);
        } catch (IOException e) {
            e.printStackTrace();
            throw new OpenIdException("Could not get OpenId server from " +
                    "identifier.", e);
        }

        Properties p = getProps(idserver.getServer());
        String handle = p.getProperty("handle");

        // todo: use delegate here, replace identity?

        AuthenticationRequest ar = AuthenticationRequest.create(identity,
                returnTo, trustRoot, handle);

        System.out.println("urlString=" + ar.toUrlString());

        return idserver.getServer() + "?" + ar.toUrlString();
    }


    /**
     * This method will attempt to authenticate against
     *
     * @param map
     * @return openid.identity if authentication was successful, null if unsuccessful
     * @throws IOException
     * @throws OpenIdException
     * @throws NoSuchAlgorithmException
     */
    public String authenticate(Map map)
            throws IOException, OpenIdException, NoSuchAlgorithmException {

        log.debug("request map in authenticate: " + map);
        AuthenticationResponse response =
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
            throw new AuthenticationException("OpenId tokens do not match! " +
                    "claimed identity: " + identity);
        }
        System.out.println("tokens match, identity is ok: " + identity);
        return identity;
	}


}
