package fitnesse.authentication;

import junit.framework.TestCase;


public class LDAPAuthenticatorTest extends TestCase {

    public void testNullUsername() throws Exception {
        LDAPAuthenticator authenticator = new LDAPAuthenticator(null);
        assertFalse(authenticator.isAuthenticated(null, "password"));
    }

    public void testNullPassword() throws Exception {
        LDAPAuthenticator authenticator = new LDAPAuthenticator(null);
        assertFalse(authenticator.isAuthenticated("username", null));
    }

    public void testNullUsernameAndPassword() throws Exception {
        LDAPAuthenticator authenticator = new LDAPAuthenticator(null);
        assertFalse(authenticator.isAuthenticated(null, null));
    }

    public void testAuthenticated() throws Exception {
        LDAPAuthenticator authenticator = new LDAPAuthenticator(null);
        assertTrue(authenticator.isAuthenticated("same", "same"));
    }

}
