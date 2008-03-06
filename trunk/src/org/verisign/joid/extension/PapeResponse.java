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
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Provider Authentication Policy Extension response message. See the
 * <a href="http://openid.net/specs/openid-provider-authentication-policy-extension-1_0-02.html">specification</a>.
 * <p>
 * Example of parsing incoming responses:
 * <pre>
 * Response resp = ResponseFactory.parse(s);
 * if (resp instanceof AuthenticationResponse) {
 *     AuthenticationResponse ar = (AuthenticationResponse) resp;
 *     PapeResponse pr = new PapeResponse(ar.getExtensions());
 *     if (pr.isValid()) {
 *         ...
 *     }
 * }
 * </pre>
 * </p>
 * 
 * <p>
 * Example of inserting PAPE response to an outgoing reponse:
 * <pre>
 * Response resp = request.processUsing(serverInfo);
 * if (resp instanceof AuthenticationResponse) {
 *     AuthenticationResponse ar = (AuthenticationResponse)resp;
 *     PapeResponse pr = new PapeResponse();
 *     pr.setAuthAge(3600);
 *     pr.setAuthPolicies(new String[] 
 *         { "http://schemas.openid.net/pape/policies/2007/06/phishing-resistant",
 *           "http://schemas.openid.net/pape/policies/2007/06/multi-factor",
 *           "http://schemas.openid.net/pape/policies/2007/06/multi-factor-physical" });
 *     pr.setNistAuthLevel(4);
 *     ar.addExtension(pr);
 * }
 * </pre>
 * </p>
 */
public class PapeResponse extends Extension implements PapeConstants {
    /**
     * PAPE response parameter: One or more authentication policy URIs
     * that the OP conformed to when authenticating the End User.  If
     * no policies were met though the OP wishes to convey other
     * information in the response, this parameter MUST be included
     * with the value of "none".
     */
    static String AUTH_POLICIES = "auth_policies";
    static String EMPTY_AUTH_POLICIES = "none";
    /**
     * PAPE response parameter: The most recent timestamp when the End
     * User has actively authenticated to the OP in a manner fitting
     * the asserted policies.  If the RP's request included the
     * "openid.max_auth_age" parameter then the OP MUST include
     * "openid.auth_time" in its response. If "openid.max_auth_age"
     * was not requested, the OP MAY choose to include
     * "openid.auth_time" in its response.
     */
    static String AUTH_TIME = "auth_time";
    /**
     * PAPE response parameter: The Assurance Level as defined by the
     * National Institute of Standards and Technology (NIST) in
     * Special Publication 800-63 corresponding to the authentication
     * method and policies employed by the OP when authenticating the
     * End User. Level 0 is not an assurance level defined by NIST,
     * but rather SHOULD be used to signify that the OP recognizes the
     * parameter and the End User authentication did not meet the
     * requirements of Level 1.
     */
    static String NIST_AUTH_LEVEL = "nist_auth_level";

    /**
     * Creates a new <code>PapeResponse</code> instance with the
     * correct namespace and an empty set of
     * attributes. <code>auth_policies</code> is initialized to the
     * empty value.
     */
    public PapeResponse () {
        super(PAPE_NAMESPACE, PAPE_IDENTIFIER);
        // AUTH_POLICIES is a mandatory parameter
        setParam(AUTH_POLICIES, EMPTY_AUTH_POLICIES);
    }

    /**
     * Creates a new <code>PapeResponse</code> instance using the
     * given parameter mappings.  Get the <code>extensionMap</code>
     * parameter from
     * <code>AuthenticationResponse.getExtensions()</code>
     *
     * @param extensionMap a <code>Map<String, String></code> containing the parameter mappings
     */
    public PapeResponse (Map extensionMap) {
        super(PAPE_NAMESPACE, extensionMap);
    }

    /**
     * Retrieve the <code>auth_time</code> parameter.
     *
     * @return the authentication age as a <code>Date</code> value
     * @exception OpenIdException if the parameter didn't parse to a Date
     * @see #AUTH_TIME
     */
    public Date getAuthTime () throws OpenIdException {
        return getDateParam(AUTH_TIME);
    }

    /**
     * Set the <code>auth_time</code> parameter with the given value.
     *
     * @param age authentication age in seconds as an <code>int</code> value
     * @see #AUTH_TIME
     */
    public void setAuthTime (int age) {
        Date now = new Date();
        long time = now.getTime();
        time -= age * 1000; // decrement time by age seconds
        setAuthTime(new Date(time));
    }

    /**
     * Set the <code>auth_time</code> parameter with the given value.
     * If <code>null</code> is specified as the value, the parameter
     * will be removed.  Remember to include auth_time in the response
     * if it was in the request.
     *
     * @param age authentication age as a <code>Date</code> value
     * @see #AUTH_TIME
     */
    public void setAuthTime (Date authTime) {
        if (authTime == null) {
            // auth_time is optional, remove it if set to null
            clearParam(AUTH_TIME);
        }
        else {
            setDateParam(AUTH_TIME, authTime);
        }
    }

    /**
     * Retrieve the <code>auth_policies</code> parameter values.
     *
     * @return authentication policies as a <code>Set<String></code> value
     * @see #AUTH_POLICIES
     */
    public Set getAuthPolicies () {
        if (getParam(AUTH_POLICIES).equals(EMPTY_AUTH_POLICIES)) {
            return new LinkedHashSet();
        }
        return getSetParam(AUTH_POLICIES, " ");
    }

    /**
     * Set the <code>auth_policies</code> parameter with the given
     * array of policy URI strings.  Duplicate URIs will be discarded.
     *
     * @param policies a set of policy URIs as a <code>String[]</code> value
     * @see #AUTH_POLICIES
     */
    public void setAuthPolicies (String[] policies) {
        setAuthPolicies(new LinkedHashSet(Arrays.asList(policies)));
    }

    /**
     * Set the <code>auth_policies</code> parameter with the given set
     * of policy URI strings.
     *
     * @param policies a set of policy URIs as a <code>Set<String></code> value
     * @see #AUTH_POLICIES
     */
    public void setAuthPolicies (Set policies) {
        if (policies.isEmpty()) {
            setParam(AUTH_POLICIES, EMPTY_AUTH_POLICIES);
        }
        else {
            setListParam(AUTH_POLICIES, policies, " ");
        }
    }

    /**
     * Retrieve the <code>nist_auth_level</code> parameter.
     *
     * @return the NIST assurance level as an <code>Integer</code> value
     * @exception OpenIdException if the parameter didn't parse to an integer
     * @see #NIST_AUTH_LEVEL
     */
    public Integer getNistAuthLevel () throws OpenIdException {
        return getIntParam(NIST_AUTH_LEVEL);
    }

    /**
     * Set the <code>nist_auth_level</code> parameter with the given
     * value.
     *
     * @param nistAuthLevel NIST assurance level as an <code>int</code> value, must be any of 0 through 4 inclusive
     * @see #NIST_AUTH_LEVEL
     */
    public void setNistAuthLevel (int nistAuthLevel) {
        setNistAuthLevel(new Integer(nistAuthLevel));
    }        

    /**
     * Set the <code>nist_auth_level</code> parameter with the given
     * value.  If <code>null</code> is specified as the value, the
     * parameter will be removed.
     *
     * @param nistAuthLevel NIST assurance level as an <code>int</code> value, must be any of 0 through 4 inclusive
     * @see #NIST_AUTH_LEVEL
     */
    public void setNistAuthLevel (Integer nistAuthLevel) {
        if (nistAuthLevel == null) {
            // nist_auth_level is optional, remove it if set to null
            clearParam(NIST_AUTH_LEVEL);
        }
        else {
            Integer minVal = new Integer(0);
            Integer maxVal = new Integer(4);
            if (nistAuthLevel.compareTo(minVal) < 0) {
                setIntParam(NIST_AUTH_LEVEL, minVal);
            }
            else if (nistAuthLevel.compareTo(maxVal) > 0) {
                setIntParam(NIST_AUTH_LEVEL, maxVal);
            }
            else {
                setIntParam(NIST_AUTH_LEVEL, nistAuthLevel);
            }
        }
    }
}
