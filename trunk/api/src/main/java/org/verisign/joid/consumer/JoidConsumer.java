package org.verisign.joid.consumer;


import org.verisign.joid.*;
import org.apache.commons.logging.LogFactory;
import org.apache.commons.logging.Log;

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
public class JoidConsumer
{

    private static Log log = LogFactory.getLog( JoidConsumer.class );

    private Map<String, Properties> propSingleton;
    private Map<String, String> handleToIdServer;
    private Discoverer discoverer = new Discoverer();


    public JoidConsumer()
    {
        log.info( "Constructor: JoidConsumer" );
    }


    private synchronized Properties getProps( String idserver )
    {
        // @TODO: just store the AssociationResponse instead of converting to props
        if ( propSingleton == null )
        {
            propSingleton = new HashMap<String, Properties>();
            handleToIdServer = new HashMap<String, String>();
        }
        Properties props = ( Properties ) propSingleton.get( idserver );
        if ( props == null )
        { // @TODO: also check expires_in time to make sure it's still valid
            try
            {
                props = associate( idserver );
                propSingleton.put( idserver, props );
                handleToIdServer.put( props.getProperty( "handle" ), idserver );
            }
            catch ( Exception e )
            {
                e.printStackTrace();
            }
        }
        return props;
    }


    private Properties getPropsByHandle( String associationHandle )
            throws OpenIdException
    {
        String idServer = ( String ) handleToIdServer.get( associationHandle );
        log.info( "got idserver for handle: " + associationHandle +
                " - " + idServer );
        if ( idServer == null )
        {
            throw new OpenIdException( "handle for server not found!" );
        }
        return getProps( idServer );
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
    public Properties associate( String idserver )
            throws IOException, OpenIdException
    {
        DiffieHellman dh = DiffieHellman.getDefault();
        Crypto crypto = new Crypto();
        crypto.setDiffieHellman( dh );

        AssociationRequest ar = AssociationRequest.create( crypto );

        log.info( "[JoidConsumer] Attempting to associate with: " + idserver );
        log.info( "Request=" + ar );

        Response response = Util.send( ar, idserver );
        log.info( "Response=" + response + "\n" );

        AssociationResponse asr = ( AssociationResponse ) response;

        Properties props = new Properties();
        props.setProperty( "idServer", idserver );
        props.setProperty( "handle", asr.getAssociationHandle() );
        props.setProperty( "publicKey",
                Crypto.convertToString( asr.getDhServerPublic() ) );
        props.setProperty( "encryptedKey",
                Crypto.convertToString( asr.getEncryptedMacKey() ) );

        BigInteger privateKey = dh.getPrivateKey();
        props.setProperty( "privateKey", Crypto.convertToString( privateKey ) );
        props.setProperty( "modulus",
                Crypto.convertToString( DiffieHellman.DEFAULT_MODULUS ) );

        props.setProperty( "_dest", idserver );
        props.setProperty( "expiresIn", "" + asr.getExpiresIn() );

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
     * <p>
     * This method is used by a relying party to create the url to redirect a
     * user to after entering their OpenId URL in a form.
     * </p>
     * <p>
     * It will find the id server found at the OpenID url, associate with the
     * server if necessary and return an authentication request url.
     * </p>
     *
     * @param identity  users OpenID url
     * @param returnTo  the url to return to after user is finished with OpenId provider
     * @param trustRoot base url that the authentication should apply to
     * @return
     * @throws OpenIdException
     */
    public String getAuthUrl( String identity, String returnTo, String trustRoot )
            throws OpenIdException
    {

        // find id server
        ServerAndDelegate idserver = null;
        try
        {
            //FIX ME is it required to do each authentication? maybe we can cache the idServer with association ! see the spec!!!
            idserver = discoverer.findIdServer( identity );
        }
        catch ( Exception e )
        {
            e.printStackTrace();
            throw new OpenIdException( "Could not get OpenId server from " +
                    "identifier.", e );
        }

        Properties p = getProps( idserver.getServer() );
        String handle = p.getProperty( "handle" );

        // todo: use delegate here, replace identity?

        AuthenticationRequest ar = AuthenticationRequest.create( identity,
                returnTo, trustRoot, handle );

        log.info( "urlString=" + ar.toUrlString() );

        return idserver.getServer() + "?" + ar.toUrlString();
    }


    /**
     * This method will attempt to authenticate against the OpenID server.
     *
     * @param map
     * @return openid.claimed_id if authentication was successful, null if unsuccessful
     * @throws IOException
     * @throws OpenIdException
     * @throws NoSuchAlgorithmException
     */
    public AuthenticationResult authenticate( Map<String,String> map, String serverEndpointURL )
            throws IOException, OpenIdException, NoSuchAlgorithmException
    {

        log.debug( "request map in authenticate: " + map );
        AuthenticationResponse response =
                new AuthenticationResponse( map );
        // @TODO: store nonce's to ensure we never accept the same value again - see sec 11.3 of spec 2.0
        //verify the return_to URL according to the OpenID specification (11.1.  Verifying the Return URL)
        if (!serverEndpointURL.equals(response.getReturnTo()))
        {
            throw new OpenIdException("Return_to verification failed.");
        }
        
        //Start discovery on the contained claimed_id and return the discovered endpoint
        String serverURL = verifyServerEndpointURL(response);
        Properties props;
        //verify if 'op_endpoint' in the token is equals the fresh discovered serverURL
        if (!serverURL.equals(response.getUrlEndPoint())) {
            throw new OpenIdException("Endpoint verification failed.");
        }
        if ( response.getInvalidateHandle() != null )
        {
            // then we have to send a authentication_request (dumb mode) to verify the signature
            props = getPropsByHandle(response.getInvalidateHandle());
            return useCheckAuthentication(response, serverURL); //use for the verificiation the keys associated to serverURL
        } else {
            // normal properties
            props = getProps(serverURL);

            if (!props.getProperty("handle").equals(response.getAssociationHandle()))
            {
                return useCheckAuthentication(response, serverURL); //use for the verificiation the keys associated to serverURL
            }
            // todo: before returning a valid response, ensure return_to is a suburl of trust_root
            BigInteger privKey = Crypto.convertToBigIntegerFromString( props.getProperty( "privateKey" ) );
            BigInteger modulus = Crypto.convertToBigIntegerFromString( props.getProperty( "modulus" ) );
            BigInteger serverPublic = Crypto.convertToBigIntegerFromString( props.getProperty( "publicKey" ) );
            byte[] encryptedKey = Crypto.convertToBytes( props.getProperty( "encryptedKey" ) );

            /* String sig = response.sign(response.getAssociationType(),
                             a.getMacKey(), response.getSignedList());
                    isValid = sig.equals(response.getSignature());
            */
            DiffieHellman dh = DiffieHellman.recreate( privKey, modulus );
            Crypto crypto = new Crypto();
            crypto.setDiffieHellman( dh );
            byte[] clearKey = crypto.decryptSecret( serverPublic, encryptedKey );

            String signature = response.getSignature();
            log.info( "Server's signature: " + signature );

            String sigList = response.getSignedList();
            String reSigned = response.sign( clearKey, sigList );
            log.info( "Our signature:      " + reSigned );
            String claimedId = response.getClaimedId();
            if ( !signature.equals( reSigned ) )
            {
                throw new AuthenticationException( "OpenID signatures do not match! " +
                        "claimed identity: " + claimedId );
            }
            log.info( "Signatures match, identity is ok: " + claimedId );
            return new AuthenticationResult( claimedId, response );
        }

    }

    private AuthenticationResult useCheckAuthentication(AuthenticationResponse response, String serverURL) 
        throws OpenIdException, AuthenticationException, IOException 
    {
        CheckAuthenticationRequest checkReq
            = new CheckAuthenticationRequest(response.toMap(), Mode.CHECK_AUTHENTICATION);
        
        CheckAuthenticationResponse response2 = (CheckAuthenticationResponse) Util.send(checkReq, serverURL);
        // @TODO: verify the invalidate_handle in response2 is the same as in response
        removeInvalidHandle(response.getInvalidateHandle());
        if (!response2.isValid()) {
            throw new AuthenticationException("Signature invalid, identity denied.");
        }
        // then this is a valid request, lets send it back
        return new AuthenticationResult(response.getClaimedId(), response);
    }

    private String verifyServerEndpointURL(AuthenticationResponse response) throws OpenIdException {
        ServerAndDelegate idserver = null;
        final String claimedId = response.getClaimedId();
        final String opEndpoint = response.getUrlEndPoint();
        
        //start discovery on the contained claimed_id and 
        //compare the discovered enpoint with the 'op_endpoint' in the token
        try {
            idserver = discoverer.findIdServer(claimedId);
        } catch (Exception e) {
            e.printStackTrace();
            throw new OpenIdException("Could not get OpenId server from "
                    + "identifier.", e);
        }
        final String serverURL = idserver.getServer(); //uses the discovered URL instead of the URL within the token for security reasons
        return serverURL;
    }

    /**
     * If openid.invalidate_handle was received, this will remove it from our
     * cache so it won't be used again.
     *
     * @param invalidateHandle
     */
    private void removeInvalidHandle( String invalidateHandle )
    {
        String idServer = ( String ) handleToIdServer.remove( invalidateHandle );
        if ( idServer != null )
        {
            propSingleton.remove( idServer );
        }
    }

}
