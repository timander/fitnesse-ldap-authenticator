package fitnesse.authentication;

import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.mockito.Matchers;
import org.mockito.Mockito;

import javax.naming.AuthenticationException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapContext;
import java.util.Properties;

import static junit.framework.Assert.*;
import static org.mockito.Mockito.*;


public class LDAPAuthenticatorTest {

	private LDAPAuthenticator authenticator;


	@Before
	public void setUp() throws Exception {
		Properties properties = new Properties();
		properties.setProperty("ldap.domain.name", "ldap");
		properties.setProperty("ldap.server.name", "localhost:389");
		properties.setProperty("ldap.queryuser.username", "queryuserName");
		properties.setProperty("ldap.queryuser.password", "queryuserPass");
		properties.setProperty("ldap.username.attribute", "sAMAccountName");
		properties.setProperty("ldap.required.group", "FitNesse-Access");
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
		assertNull(propertiesWithMissingKeys.get("ldap.server.url"));
		authenticator.properties = propertiesWithMissingKeys;
		assertFalse(authenticator.isAuthenticated("username", "password"));
	}


	@Test
	@Ignore
	public void testAuthenticated() throws Exception {
		LdapContextFactory mockFactory = mock(LdapContextFactory.class);
		LdapContext mockContext = Mockito.mock(LdapContext.class);
		when(mockFactory.create(Matchers.anyString(), Matchers.isA(Properties.class))).thenReturn(mockContext);
		NamingEnumeration mockSearchResults = Mockito.mock(NamingEnumeration.class);
		when(mockContext.search(Matchers.anyString(), Matchers.anyString(), Matchers.isA(SearchControls.class))).thenReturn(mockSearchResults);
		when(mockSearchResults.hasMore()).thenReturn(true);
		SearchResult mockSearchResult = Mockito.mock(SearchResult.class, RETURNS_DEEP_STUBS);
		when(mockSearchResults.next()).thenReturn(mockSearchResult);
		BasicAttribute basicAttribute = new BasicAttribute("memberOf: CN=FitNesse-Access,OU=Security Groups,DC=QAnets,DC=ISLLCQA,DC=org");
		when(mockSearchResult.getAttributes().get("memberOf")).thenReturn(basicAttribute);
		when(mockSearchResult.getAttributes().size()).thenReturn(1);
		BasicAttributes basicAttributes = new BasicAttributes();
		basicAttributes.put(basicAttribute);
		when(mockContext.getAttributes("memberOf", new String[]{"CN"})).thenReturn(basicAttributes);
		authenticator.ldapContextFactory = mockFactory;
		boolean authenticated = authenticator.isAuthenticated("username", "password");
		assertTrue(authenticated);
	}


	@Test
	public void testAuthenticationFailed_AuthenticationException() throws Exception {
		LdapContextFactory mockFactory = mock(LdapContextFactory.class);
		when(mockFactory.create(Matchers.anyString(), Matchers.isA(Properties.class))).thenThrow(new AuthenticationException());
		authenticator.ldapContextFactory = mockFactory;
		assertFalse(authenticator.isAuthenticated("username", "password"));
	}


	@Test
	@Ignore
	public void testAuthenticateWithRealActiveDirectorySever() throws Exception {
		Properties properties = new Properties();
		properties.setProperty("ldap.domain.name", "testdomain");
		properties.setProperty("ldap.server.name", "testldapserver");
		properties.setProperty("ldap.username.attribute", "sAMAccountName");
		properties.setProperty("ldap.queryuser.username", "queryuser");
		properties.setProperty("ldap.queryuser.password", "querypass");
		properties.setProperty("ldap.required.group", "testgroup");
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
