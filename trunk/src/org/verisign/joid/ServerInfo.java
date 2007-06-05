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

package org.verisign.joid;

// import java.math.BigInteger;
// import java.security.InvalidKeyException;
// import java.security.MessageDigest;
// import java.security.NoSuchAlgorithmException;
// import java.security.SecureRandom;
// import javax.crypto.Mac;
// import javax.crypto.SecretKey;
// import javax.crypto.spec.SecretKeySpec;
// import org.apache.log4j.Logger;
// import org.apache.tsik.datatypes.Base64;
// import org.apache.tsik.uuid.UUID;
// import org.verisign.joid.AssociationRequest;
// import org.verisign.joid.Crypto;

/**
 * Information about this server.
 */
public class ServerInfo
{
    private String urlEndPoint;
    private Store store;
    private Crypto crypto;

    /**
     * Creates an instance of the server information.
     *
     * @param urlEndPoint the URL endpoint for the service. 
     * @param store the store implementation to use.
     * @param crypto the crypto implementation to use.
     */
    public ServerInfo(String urlEndPoint, Store store, Crypto crypto)
    {
	this.urlEndPoint = urlEndPoint;
	this.store = store;
	this.crypto = crypto;
    }

    String getUrlEndPoint(){return urlEndPoint;}
    Store getStore(){return store;}
    Crypto getCrypto(){return crypto;}
}
