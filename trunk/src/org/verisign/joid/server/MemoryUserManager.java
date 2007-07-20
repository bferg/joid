package org.verisign.joid.server;

import org.verisign.joid.server.UserManager;
import org.verisign.joid.server.User;

import java.util.Map;
import java.util.HashMap;

/**
 * User: treeder
 * Date: Jul 17, 2007
 * Time: 5:33:31 PM
 */
public class MemoryUserManager implements UserManager {
	private Map/*<String, User>*/ userMap = new HashMap();

	public User getUser(String username) {
		return (User) userMap.get(username);
	}

	public void save(User user) {
		userMap.put(user.getUsername(), user);
	}
}
