package examples.server;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.ListIterator;
import org.verisign.joid.Association;
import org.verisign.joid.AssociationRequest;
import org.verisign.joid.Crypto;
import org.verisign.joid.OpenIdException;
import org.verisign.joid.Store;


public class MemoryStore extends Store
{
    private static List list = new ArrayList();

    public Association generateAssociation(AssociationRequest req, 
					   Crypto crypto) 
	throws OpenIdException
    {
	// boldly reusing the db implementation of Association
	org.verisign.joid.db.Association a 
	    = new org.verisign.joid.db.Association();
	a.setMode("unused");
	a.setHandle(Crypto.generateHandle());
	a.setSessionType(req.getSessionType());

	byte[] secret = null;
	if (req.isNotEncrypted()){
	    secret = crypto.generateSecret(req.getAssociationType());
	} else {
	    secret = crypto.generateSecret(req.getSessionType());
	    crypto.setDiffieHellman(req.getDhModulus(), req.getDhGenerator());
	    byte[] encryptedSecret 
		= crypto.encryptSecret(req.getDhConsumerPublic(), secret);
	    a.setEncryptedMacKey(encryptedSecret);
	    a.setPublicDhKey(crypto.getPublicKey());
	}
	a.setMacKey(secret);
	a.setIssuedDate(new Date());
	a.setLifetime(new Long(300));

	a.setAssociationType(req.getAssociationType());
	return a;
    }

    public void saveAssociation(Association a)
    {
	list.add(a);
    }

    public void deleteAssociation(Association a)
    {
	throw new RuntimeException("not yet implemented");
	// "list.delete(a)"
    }

    public Association findAssociation(String handle) throws OpenIdException
    {
	if (handle == null) return null;
	ListIterator li = list.listIterator();
	while (li.hasNext()){
	    Association a = (Association) li.next();
	    if (handle.equals(a.getHandle())){
		return a;
	    }
	}
	return null;
    }
}
