
package org.verisign.joid;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import junit.framework.TestCase;

public class TestQueryPatternMatching extends TestCase
{

    
    public void testIsAuthenticationRequest()
    {
        Pattern openIdModePattern = Pattern.compile( ".*openid.mode=(.+?)&.*" );
        
        Matcher matcher = openIdModePattern.matcher( "openid.trust_root=http://localhost:8080&openid.ns=http://specs.openid" +
".net/auth/2.0&openid.identity=http://localhost:8180/user/usr_12658&openid.claimed_id=http://localhost:8180/user/usr_12658&openid.mode=checkid_setup&openid.realm" +
"=http://localhost:8080&openid.assoc_handle=ab7bc230-b3d7-11e0-bf49-b577fecdd34d&openid.return_to=http://localhost:8080" );
        
        assertTrue(  matcher.find() );
        
        assertTrue ( Mode.parse( matcher.group(1) ).equals( Mode.CHECKID_SETUP ) );
        
    }
}
