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

import java.util.Map;

/**
 * Represents a store that is used by JOID for persisting associations.
 */
public abstract class Store
{
    /**
     * Override constructor in the Store implementation.
     */
    protected Store() {}

    /**
     * Generates and returns association. To store the association
     * use {@link Store#saveAssociation(Association) saveAssociation()}
     *
     * @param req the association request.
     * @param crypto the crypto implementation to use.
     * @return the generated assocation.
     *
     * @throws OpenIdException at unrecoverable errors.
     */
    public abstract Association generateAssociation(AssociationRequest req, 
						    Crypto crypto)
	throws OpenIdException;

    /**
     * Deletes an association from the store.
     *
     * @param a the association to delete.
     */
    public abstract void deleteAssociation(Association a);

    /**
     * Saves an association in the store.
     *
     * @param a the association to store.
     */
    public abstract void saveAssociation(Association a);

    /**
     * Finds an association in the store.
     *
     * @param handle the handle of the association to find.
     * @return the assocation if found; null otherwise.
     *
     * @throws OpenIdException at unrecoverable errors.
     */
    public abstract Association findAssociation(String handle)
	throws OpenIdException;
}
