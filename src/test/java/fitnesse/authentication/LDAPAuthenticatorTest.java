package fitnesse.authentication;

import junit.framework.TestCase;
import org.mockito.Matchers;
import static org.mockito.Mockito.*;
import javax.naming.AuthenticationException;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.util.Hashtable;
import java.util.Properties;


@SuppressWarnings({"UseOfObsoleteCollectionType", "RawUseOfParameterizedType", "ThrowableInstanceNeverThrown"})
public class LDAPAuthenticatorTest extends TestCase {

    private LDAPAuthenticator authenticator;

    @Override
    protected void setUp() throws Exception {
        super.setUp();
        Properties properties = new Properties();
        properties.setProperty("ldap.search.base", "ou=People,dc=example,dc=com");
        properties.setProperty("ldap.server.url", "ldap://ldap.example.com:389");
        properties.setProperty("ldap.username.attribute", "AccountName");
        authenticator = new LDAPAuthenticator(properties);
    }

    public void testNullUsername() throws Exception {
        assertFalse(authenticator.isAuthenticated(null, "password"));
    }

    public void testNullPassword() throws Exception {
        assertFalse(authenticator.isAuthenticated("username", null));
    }

    public void testNullUsernameAndPassword() throws Exception {
        assertFalse(authenticator.isAuthenticated(null, null));
    }

    public void testNullProperties() throws Exception {
        assertFalse(authenticator.isAuthenticated("username", "password"));
    }

    @SuppressWarnings({"UseOfPropertiesAsHashtable"})
    public void testMissingProperties() throws Exception {
        Properties propertiesWithMissingKeys = new Properties();
        propertiesWithMissingKeys.setProperty("ldap.search.base", "search base");
        assertNull(propertiesWithMissingKeys.get("ldap.server.url"));
        authenticator.properties = propertiesWithMissingKeys;
        assertFalse(authenticator.isAuthenticated("username", "password"));
    }

    @SuppressWarnings({"JNDIResourceOpenedButNotSafelyClosed"})
    public void testAuthenticated() throws Exception {
        InitialDirContextFactory mockFactory = mock(InitialDirContextFactory.class);
        when(mockFactory.create(Matchers.isA(Hashtable.class))).thenReturn(new InitialDirContext());
        authenticator.initialDirContextFactory = mockFactory;
        assertTrue(authenticator.isAuthenticated("username", "password"));
    }

    public void testAuthenticationFailed_NamingException() throws Exception {
        InitialDirContextFactory mockFactory = mock(InitialDirContextFactory.class);
        when(mockFactory.create(Matchers.isA(Hashtable.class))).thenThrow(new NamingException());
        assertFalse(authenticator.isAuthenticated("username", "password"));
    }

    public void testAuthenticationFailed_AuthenticationException() throws Exception {
        InitialDirContextFactory mockFactory = mock(InitialDirContextFactory.class);
        when(mockFactory.create(Matchers.isA(Hashtable.class))).thenThrow(new AuthenticationException());
        authenticator.initialDirContextFactory = mockFactory;
        assertFalse(authenticator.isAuthenticated("username", "password"));
    }

    public void testSecurityContextPrincipal() throws Exception {
        CollaboratingFactory collaboratingFactory = new CollaboratingFactory();
        authenticator.initialDirContextFactory = collaboratingFactory;
        authenticator.isAuthenticated("username", "password");
        assertEquals("AccountName=username,ou=People,dc=example,dc=com?AccountName?sub?(objectClass=*)", collaboratingFactory.get(Context.SECURITY_PRINCIPAL));
        assertEquals("ldap://ldap.example.com:389/ou=People,dc=example,dc=com", collaboratingFactory.get(Context.PROVIDER_URL));
        assertEquals("simple", collaboratingFactory.get(Context.SECURITY_AUTHENTICATION));
        assertEquals("password", collaboratingFactory.get(Context.SECURITY_CREDENTIALS));
        assertEquals("com.sun.jndi.ldap.LdapCtxFactory", collaboratingFactory.get(Context.INITIAL_CONTEXT_FACTORY));
    }

    private static class CollaboratingFactory extends InitialDirContextFactory {

        public String get(String key) {
            return (String) hashtable.get(key);
        }

        public Hashtable hashtable;

        @SuppressWarnings({"AssignmentToCollectionOrArrayFieldFromParameter"})
        @Override
        public DirContext create(Hashtable env) throws NamingException {
            hashtable = env;
            return super.create(env);
        }
    }
}
