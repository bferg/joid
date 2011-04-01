package org.verisign.joid;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.thoughtworks.selenium.DefaultSelenium;
import com.thoughtworks.selenium.SeleneseTestCase;

public class TestOpRpIntegration extends SeleneseTestCase {
	@Before
	public void setUp() throws Exception {
		selenium = new DefaultSelenium("localhost", 4444, "*chrome", "http://localhost:8080/");
		selenium.start();
	}

	@Test
	public void test() throws Exception {
		selenium.open("/index.jsp");
		selenium.click("//input[@value='Login']");
		selenium.waitForPageToLoad("30000");
		selenium.type("username", "austinpowers");
		selenium.click("newuser");
		selenium.click("//input[@value='Submit']");
		selenium.waitForPageToLoad("30000");
		selenium.click("link=Logout");
		selenium.waitForPageToLoad("30000");
	}

	@After
	public void tearDown() throws Exception {
		selenium.stop();
	}
}