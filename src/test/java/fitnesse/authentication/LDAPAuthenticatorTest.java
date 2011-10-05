package fitnesse.authentication;

import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import javax.naming.AuthenticationException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.SearchControls;
import javax.naming.ldap.LdapContext;
import java.util.Properties;

import static junit.framework.Assert.*;
import static org.mockito.Mockito.*;


public class LDAPAuthenticatorTest {

    private LDAPAuthenticator authenticator;


    @Before
    public void setUp() throws Exception {
        Properties properties = new Properties();
        properties.setProperty("ldap.domain.name", "mysub.mydomain.org");
        properties.setProperty("ldap.server.name", "myldapserver");
        properties.setProperty("ldap.queryuser.username", "queryuserName");
        properties.setProperty("ldap.queryuser.password", "queryuserPass");
        properties.setProperty("ldap.username.attribute", "sAMAccountName");
        properties.setProperty("ldap.security.group", "FitNesse-Access");
        authenticator = new LDAPAuthenticator(properties);
        authenticator.ldapContextFactory = new CollaboratingFactory();
    }


    @Test
    public void testNullUsername() throws Exception {
        assertFalse(authenticator.isAuthenticated(null, "password"));
    }


    @Test
    public void testNullPassword() throws Exception {
        assertFalse(authenticator.isAuthenticated("username", null));
    }


    @Test
    public void testNullUsernameAndPassword() throws Exception {
        assertFalse(authenticator.isAuthenticated(null, null));
    }


    @Test
    public void testNullProperties() throws Exception {
        authenticator.properties = null;
        assertFalse(authenticator.isAuthenticated("username", "password"));
    }


    @Test
    public void testMissingProperties() throws Exception {
        Properties propertiesWithMissingKeys = new Properties();
        propertiesWithMissingKeys.setProperty("ldap.search.base", "search base");
        assertNull(propertiesWithMissingKeys.getProperty("ldap.server.url"));
        authenticator.properties = propertiesWithMissingKeys;
        assertFalse(authenticator.isAuthenticated("username", "password"));
    }

    @Test
    public void testLdapUrl() throws Exception {
        LdapContextFactory mockFactory = mock(LdapContextFactory.class);
        LdapContext mockContext = mock(LdapContext.class);
        NamingEnumeration mockSearchResults = mock(NamingEnumeration.class);
        when(mockFactory.create(anyString(), isA(Properties.class))).thenReturn(mockContext);
        when(mockContext.search(anyString(), anyString(), isA(SearchControls.class))).thenReturn(mockSearchResults);
        when(mockSearchResults.hasMore()).thenReturn(true);
        authenticator.ldapContextFactory = mockFactory;
        assertTrue(authenticator.isAuthenticated("username", "password"));
        verify(mockFactory).create(eq("ldaps://myldapserver.mysub.mydomain.org/"), isA(Properties.class));
    }

    @Test
    public void testUserNotFound() throws Exception {
        LdapContextFactory mockFactory = mock(LdapContextFactory.class);
        LdapContext mockContext = mock(LdapContext.class);
        NamingEnumeration mockSearchResults = mock(NamingEnumeration.class);
        when(mockFactory.create(anyString(), isA(Properties.class))).thenReturn(mockContext);
        when(mockContext.search(anyString(), anyString(), isA(SearchControls.class))).thenReturn(mockSearchResults);
        when(mockSearchResults.hasMore()).thenReturn(false);
        authenticator.ldapContextFactory = mockFactory;
        assertFalse(authenticator.isAuthenticated("username", "password"));
    }

    @Test
    public void testSearchBaseSyntax() throws Exception {
        LdapContextFactory mockFactory = mock(LdapContextFactory.class);
        LdapContext mockContext = mock(LdapContext.class);
        when(mockFactory.create(anyString(), isA(Properties.class))).thenReturn(mockContext);
        NamingEnumeration mockSearchResults = mock(NamingEnumeration.class);
        when(mockContext.search(anyString(), anyString(), isA(SearchControls.class))).thenReturn(mockSearchResults);
        when(mockSearchResults.hasMore()).thenReturn(true);
        authenticator.ldapContextFactory = mockFactory;
        boolean authenticated = authenticator.isAuthenticated("username", "password");
        assertTrue(authenticated);
        verify(mockContext).search(eq("DC=mysub,DC=mydomain,DC=org"), anyString(), isA(SearchControls.class));
    }

    @Test
    public void testLdapQuerySyntaxWithSecurityGroup() throws Exception {
        LdapContextFactory mockFactory = mock(LdapContextFactory.class);
        LdapContext mockContext = mock(LdapContext.class);
        when(mockFactory.create(anyString(), isA(Properties.class))).thenReturn(mockContext);
        NamingEnumeration mockSearchResults = mock(NamingEnumeration.class);
        when(mockContext.search(anyString(), anyString(), isA(SearchControls.class))).thenReturn(mockSearchResults);
        when(mockSearchResults.hasMore()).thenReturn(true);
        authenticator.ldapContextFactory = mockFactory;
        boolean authenticated = authenticator.isAuthenticated("username", "password");
        assertTrue(authenticated);
        String expectedLdapQuerySyntax
                = "(&(sAMAccountName=username)(objectClass=user)(userPrincipalName=username@mysub.mydomain.org)" +
                  "(memberOf=CN=FitNesse-Access,OU=Security Groups,DC=mysub,DC=mydomain,DC=org)))";
        verify(mockContext).search(anyString(), eq(expectedLdapQuerySyntax), isA(SearchControls.class));
    }

    @Test
    public void testLdapQuerySyntaxWithoutSecurityGroup() throws Exception {
        LdapContextFactory mockFactory = mock(LdapContextFactory.class);
        LdapContext mockContext = mock(LdapContext.class);
        when(mockFactory.create(anyString(), isA(Properties.class))).thenReturn(mockContext);
        NamingEnumeration mockSearchResults = mock(NamingEnumeration.class);
        when(mockContext.search(anyString(), anyString(), isA(SearchControls.class))).thenReturn(mockSearchResults);
        when(mockSearchResults.hasMore()).thenReturn(true);
        authenticator.ldapContextFactory = mockFactory;
        authenticator.properties.remove("ldap.security.group");
        boolean authenticated = authenticator.isAuthenticated("username", "password");
        assertTrue(authenticated);
        String expectedLdapQuerySyntax
                = "(&(sAMAccountName=username)(objectClass=user)(userPrincipalName=username@mysub.mydomain.org))";
        verify(mockContext).search(anyString(), eq(expectedLdapQuerySyntax), isA(SearchControls.class));
    }


    @Test
    public void testAuthenticated() throws Exception {
        LdapContextFactory mockFactory = mock(LdapContextFactory.class);
        LdapContext mockContext = mock(LdapContext.class);
        when(mockFactory.create(anyString(), isA(Properties.class))).thenReturn(mockContext);
        NamingEnumeration mockSearchResults = mock(NamingEnumeration.class);
        when(mockContext.search(anyString(), anyString(), isA(SearchControls.class))).thenReturn(mockSearchResults);
        when(mockSearchResults.hasMore()).thenReturn(true);
        authenticator.ldapContextFactory = mockFactory;
        boolean authenticated = authenticator.isAuthenticated("username", "password");
        assertTrue(authenticated);
    }


    @Test
    public void testAuthenticationFailed_AuthenticationException() throws Exception {
        LdapContextFactory mockFactory = mock(LdapContextFactory.class);
        when(mockFactory.create(anyString(), isA(Properties.class))).thenThrow(new AuthenticationException());
        authenticator.ldapContextFactory = mockFactory;
        assertFalse(authenticator.isAuthenticated("username", "password"));
    }


    @Test
    @Ignore
    public void testAuthenticateWithRealActiveDirectorySever() throws Exception {
        Properties properties = new Properties();
        properties.setProperty("ldap.domain.name", "mysub.mydomain.org");
        properties.setProperty("ldap.server.name", "myldapserver");
        properties.setProperty("ldap.username.attribute", "sAMAccountName");
        properties.setProperty("ldap.queryuser.username", "queryuser");
        properties.setProperty("ldap.queryuser.password", "querypass");
        properties.setProperty("ldap.security.group", "securitygroup");
        try {
            boolean authentication = new LDAPAuthenticator(properties).isAuthenticated("testuser", "testpass");
            assertTrue(authentication);
        }
        catch (Exception e) {
            fail("Authentication Failed..." + e.getMessage());
        }
    }


    @Test
    public void testDomainToSearchBase() {
        assertEquals("DC=prefix,DC=domainname,DC=tld", new LDAPAuthenticator(null).domainToSearchBase("prefix.domainname.tld"));
        assertEquals("", new LDAPAuthenticator(null).domainToSearchBase(""));
    }


    private static class CollaboratingFactory extends LdapContextFactory {

        public Properties props;
        public String url;


        public String get(String key) {
            return props.getProperty(key);
        }


        @Override
        public LdapContext create(String url, Properties env) throws NamingException {
            props = env;
            this.url = url;
            return super.create(url, env);
        }
    }
}
