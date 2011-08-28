package org.verisign.joid;


import junit.framework.TestCase;


public class TestQueryPatternMatching extends TestCase
{

    public void testIsAuthenticationRequest() throws InvalidOpenIdQueryException
    {
        String modeParamAtEnd = "openid.identity=http%3A%2F%2Fbirkan.softera.com.tr%3A8080%2Fuser%2Fbduman&openid.assoc_handle=7053dd10-d109-11e0-bbe8-f57bc9d57ad6&openid.return_to=http%3A%2F%2Flocalhost%3A54347%2FUser%2FAuthenticate%3FReturnUrl%3DIndex%26dnoa.userSuppliedIdentifier%3Dhttp%253A%252F%252Fbirkan.softera.com.tr%253A8080%252Fuser%252Fbduman%26dnoa.op_endpoint%3Dhttp%253A%252F%252Fbirkan.softera.com.tr%253A8080%252Flogin%26dnoa.claimed_id%3Dhttp%253A%252F%252Fbirkan.softera.com.tr%253A8080%252Fuser%252Fbduman%26dnoa.request_nonce%3DzwGtePYzzgjwIOz%252BqcBFua42NkoKJ%252BJQ%26dnoa.return_to_sig_handle%3D%257B634501731185404127%257D%257Bkyma5A%253D%253D%257D%26dnoa.return_to_sig%3D0lvdAhbAkf2ZmUi7AG0aaFndmbDMQimq6qmG4z%252BTUPiD7V4SpCU%252B3%252FwWwplRL1WAUq1n5jBvplPP99wIn4VDig%253D%253D&openid.trust_root=http%3A%2F%2Flocalhost%3A54347%2F&openid.mode=checkid_setup";
        String modeParamAtStart = "openid.mode=checkid_setup&openid.identity=http%3A%2F%2Fbirkan.softera.com.tr%3A8080%2Fuser%2Fbduman&openid.assoc_handle=7053dd10-d109-11e0-bbe8-f57bc9d57ad6&openid.return_to=http%3A%2F%2Flocalhost%3A54347%2FUser%2FAuthenticate%3FReturnUrl%3DIndex%26dnoa.userSuppliedIdentifier%3Dhttp%253A%252F%252Fbirkan.softera.com.tr%253A8080%252Fuser%252Fbduman%26dnoa.op_endpoint%3Dhttp%253A%252F%252Fbirkan.softera.com.tr%253A8080%252Flogin%26dnoa.claimed_id%3Dhttp%253A%252F%252Fbirkan.softera.com.tr%253A8080%252Fuser%252Fbduman%26dnoa.request_nonce%3DzwGtePYzzgjwIOz%252BqcBFua42NkoKJ%252BJQ%26dnoa.return_to_sig_handle%3D%257B634501731185404127%257D%257Bkyma5A%253D%253D%257D%26dnoa.return_to_sig%3D0lvdAhbAkf2ZmUi7AG0aaFndmbDMQimq6qmG4z%252BTUPiD7V4SpCU%252B3%252FwWwplRL1WAUq1n5jBvplPP99wIn4VDig%253D%253D&openid.trust_root=http%3A%2F%2Flocalhost%3A54347%2F";
        String modeParamAtAtSomeOtherPlace = "openid.identity=http%3A%2F%2Fbirkan.softera.com.tr%3A8080%2Fuser%2Fbduman&openid.mode=checkid_setup&openid.assoc_handle=7053dd10-d109-11e0-bbe8-f57bc9d57ad6&openid.return_to=http%3A%2F%2Flocalhost%3A54347%2FUser%2FAuthenticate%3FReturnUrl%3DIndex%26dnoa.userSuppliedIdentifier%3Dhttp%253A%252F%252Fbirkan.softera.com.tr%253A8080%252Fuser%252Fbduman%26dnoa.op_endpoint%3Dhttp%253A%252F%252Fbirkan.softera.com.tr%253A8080%252Flogin%26dnoa.claimed_id%3Dhttp%253A%252F%252Fbirkan.softera.com.tr%253A8080%252Fuser%252Fbduman%26dnoa.request_nonce%3DzwGtePYzzgjwIOz%252BqcBFua42NkoKJ%252BJQ%26dnoa.return_to_sig_handle%3D%257B634501731185404127%257D%257Bkyma5A%253D%253D%257D%26dnoa.return_to_sig%3D0lvdAhbAkf2ZmUi7AG0aaFndmbDMQimq6qmG4z%252BTUPiD7V4SpCU%252B3%252FwWwplRL1WAUq1n5jBvplPP99wIn4VDig%253D%253D&openid.trust_root=http%3A%2F%2Flocalhost%3A54347%2F";
        
        OpenId openId = new OpenId( null );

        assertTrue ( openId.isAuthenticationRequest( modeParamAtStart ) );
        assertTrue ( openId.isAuthenticationRequest( modeParamAtEnd ) );
        assertTrue ( openId.isAuthenticationRequest( modeParamAtAtSomeOtherPlace ) );
    }

}
