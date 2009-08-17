package fitnesse.authentication;

import junit.framework.TestCase;
import org.mockito.Matchers;
import static org.mockito.Mockito.*;
import javax.naming.AuthenticationException;
import javax.naming.NamingException;
import javax.naming.directory.InitialDirContext;
import java.util.Hashtable;


@SuppressWarnings({"UseOfObsoleteCollectionType", "RawUseOfParameterizedType", "ThrowableInstanceNeverThrown"})
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

    @SuppressWarnings({"JNDIResourceOpenedButNotSafelyClosed"})
    public void testAuthenticated() throws Exception {
        LDAPAuthenticator authenticator = new LDAPAuthenticator(null);
        InitialDirContextFactory mockFactory = mock(InitialDirContextFactory.class);
        when(mockFactory.create(Matchers.isA(Hashtable.class))).thenReturn(new InitialDirContext());
        authenticator.initialDirContextFactory = mockFactory;
        assertTrue(authenticator.isAuthenticated("username", "password"));
    }

    public void testAuthenticationFailed_NamingException() throws Exception {
        LDAPAuthenticator authenticator = new LDAPAuthenticator(null);
        InitialDirContextFactory mockFactory = mock(InitialDirContextFactory.class);
        when(mockFactory.create(Matchers.isA(Hashtable.class))).thenThrow(new NamingException());
        assertFalse(authenticator.isAuthenticated("username", "password"));
    }

    public void testAuthenticationFailed_AuthenticationException() throws Exception {
        LDAPAuthenticator authenticator = new LDAPAuthenticator(null);
        InitialDirContextFactory mockFactory = mock(InitialDirContextFactory.class);
        when(mockFactory.create(Matchers.isA(Hashtable.class))).thenThrow(new AuthenticationException());
        authenticator.initialDirContextFactory = mockFactory;
        assertFalse(authenticator.isAuthenticated("username", "password"));
    }


}
