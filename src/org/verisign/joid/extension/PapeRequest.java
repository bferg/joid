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

package org.verisign.joid.extension;

import org.verisign.joid.OpenIdException;

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Provider Authentication Policy Extension request message. See the
 * <a href="http://openid.net/specs/openid-provider-authentication-policy-extension-1_0-02.html">specification</a>.
 * <p>
 * Example of parsing incoming requests:
 * <pre>
 *     AuthenticationRequest ar = (AuthenticationRequest) req;
 *     PapeRequest pr = new PapeRequest(ar.getExtensions());
 *     if (pr.isValid()) {
 *         ...
 *     }
 * }
 * </pre>
 * </p>
 * 
 * <p>
 * Example of inserting PAPE request to an outgoing request:
 * <pre>
 * AuthenticationRequest ar = AuthenticationRequest.create(identity,
 *                                                         returnTo,
 *                                                         trustRoot,
 *                                                         assocHandle);
 * PapeRequest pr = new PapeRequest();
 * pr.setMaxAuthAge(3600);
 * ar.addExtension(pr);
 * </pre>
 * </p>
 */
public class PapeRequest extends Extension implements PapeConstants {
    /** 
     * PAPE request parameter: If the End User has not actively
     * authenticated to the OP within the number of seconds specified
     * in a manner fitting the requested policies, the OP SHOULD
     * authenticate the End User for this request.  Value: Integer
     * value greater than or equal to zero in seconds, and is
     * optional.
     */
    static String MAX_AUTH_AGE = "max_auth_age";
    /**
     * PAPE request parameter: Zero or more authentication policy URIs
     * that the OP SHOULD conform to when authenticating the user. If
     * multiple policies are requested, the OP SHOULD satisfy as many
     * as it can.
     */
    static String PREFERRED_AUTH_POLICIES = "preferred_auth_policies";

    /**
     * Construct <code>PapeRequest</code> object with the correct
     * namespace and an empty set of attributes.
     * <code>preferred_auth_policies</code> is initialized to an empty
     * string.
     */
    public PapeRequest () {
        super(PAPE_NAMESPACE, PAPE_IDENTIFIER);
        // PREFERRED_AUTH_POLICIES is a mandatory parameter, default
        // to none
        setParam(PREFERRED_AUTH_POLICIES, "");
    }

    /**
     * Construct <code>PapeRequest</code> object using the given
     * parameter mappings.  Get the <code>extensionMap</code>
     * parameter from
     * <code>AuthenticationRequest.getExtensions</code>.
     *
     * @param extensionMap a <code>Map<String, String></code> containing the parameter mappings
     */
    public PapeRequest (Map extensionMap) {
        super(PAPE_NAMESPACE, extensionMap);
    }

    /**
     * Retrieve the <code>max_auth_age</code> parameter.
     *
     * @return the maximum authentication age as an <code>Integer</code> value
     * @exception OpenIdException if the parameter didn't parse to an integer
     * @see #MAX_AUTH_AGE
     */
    public Integer getMaxAuthAge () throws OpenIdException {
        return getIntParam(MAX_AUTH_AGE);
    }

    /**
     * Set the <code>max_auth_age</code> parameter with the given
     * value.
     *
     * @param age maximum authentication age as an <code>int</code> value
     * @see #MAX_AUTH_AGE
     */
    public void setMaxAuthAge (int age) {
        setMaxAuthAge(new Integer(age));
    }

    /**
     * Set the <code>max_auth_age</code> parameter with the given
     * value.  If <code>null</code> is specified as the value, the
     * parameter will be removed.
     *
     * @param age maximum authentication age as an <code>Integer</code> value
     * @see #MAX_AUTH_AGE
     */
    public void setMaxAuthAge (Integer age) {
        if (age == null) {
            // max_auth_age is optional, remove it if set to null
            clearParam(MAX_AUTH_AGE);
        }
        else {
            Integer minVal = new Integer(0);
            if (age.compareTo(minVal) < 0) {
                setIntParam(MAX_AUTH_AGE, minVal);
            }
            else {
                setIntParam(MAX_AUTH_AGE, age);
            }
        }
    }

    /**
     * Retrieve the <code>preferred_auth_policies</code> parameter
     * values.
     *
     * @return preferred authentication policies as a <code>Set<String></code> value
     * @see #PREFERRED_AUTH_POLICIES
     */
    public Set getPreferredAuthPolicies () {
        return getSetParam(PREFERRED_AUTH_POLICIES, " ");
    }

    /**
     * Set the <code>preferred_auth_policies</code> parameter with the
     * given array of policy URI strings.  Duplicate URIs will be
     * discarded.
     *
     * @param policies a set of policy URIs as a <code>String[]</code> value
     * @see #PREFERRED_AUTH_POLICIES
     */
    public void setPreferredAuthPolicies (String[] policies) {
        setPreferredAuthPolicies(new LinkedHashSet(Arrays.asList(policies)));
    }

    /**
     * Set the <code>preferred_auth_policies</code> parameter with the
     * given set of policy URI strings.
     *
     * @param policies a set of policy URIs as a <code>Set<String></code> value
     * @see #PREFERRED_AUTH_POLICIES
     */
    public void setPreferredAuthPolicies (Set policies) {
        setListParam(PREFERRED_AUTH_POLICIES, policies, " ");
    }
}
