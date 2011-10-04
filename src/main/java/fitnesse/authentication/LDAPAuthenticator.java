package fitnesse.authentication;

import javax.naming.AuthenticationException;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapContext;
import java.util.Properties;


@SuppressWarnings({"ProtectedField"})
public class LDAPAuthenticator extends Authenticator {

	protected Properties properties;
	protected LdapContextFactory ldapContextFactory = new LdapContextFactory();
	private static final String DIGEST_MD5_AUTHENTICATION = "DIGEST-MD5";


	@SuppressWarnings({"AssignmentToCollectionOrArrayFieldFromParameter"})
	public LDAPAuthenticator(Properties properties) {
		this.properties = properties;
	}


	@Override
	public boolean isAuthenticated(String username, String password) throws Exception {
		if (username == null || password == null) return false;

		String usernameAttribute = getProperty("ldap.username.attribute");
		String domainName = getProperty("ldap.domain.name");
		String serverName = getProperty("ldap.server.name");
		String queryUsername = getProperty("ldap.queryuser.username");
		String queryPassword = getProperty("ldap.queryuser.password");
		String requiredGroup = getProperty("ldap.required.group");
		String ldapURL = "ldaps://" + serverName + "." + domainName + '/';

		log("Authenticating " + username + " through " + ldapURL);

		boolean authenticated = false;
		LdapContext context = null;
		try {
			Properties props = setupAuthorizedEnv(queryUsername, queryPassword);
			context = ldapContextFactory.create(ldapURL, props);
			log("Authentication succeeded for query user");

			SearchControls controls = new SearchControls();
			controls.setSearchScope(SearchControls.SUBTREE_SCOPE);

            applyUserAuthentication(context, username, password);

            String userPrincipalName = username + "@" + domainName;
            String searchBase = domainToSearchBase(domainName);
            String secureGroupRestriction = "(memberOf=CN=" + requiredGroup + ",OU=Security Groups," + searchBase + "))";
            String ldapQuery = "(&(" + usernameAttribute + "=" + username + ")(objectClass=user)" +
                            "(userPrincipalName=" + userPrincipalName + ")" + secureGroupRestriction + ")";
            log(ldapQuery);
            NamingEnumeration<SearchResult> searchResults = context.search(searchBase, ldapQuery, controls);
			if (searchResults.hasMore()) {
                authenticated = true;
                log("Authenticated succedded for " + username);
            }
            log("Cannot locate user information for " + username);
        }
		catch (AuthenticationException a) {
			log("Authentication failed: " + a);
		}
		catch (NamingException e) {
			log("Failed to bind to LDAP / get account information: " + e);
		}
		finally {
			if (context != null) context.close();
		}
		return authenticated;
	}

	private Properties setupAuthorizedEnv(String queryUsername, String queryPassword) {
		Properties authEnvProperties = new Properties();
		authEnvProperties.setProperty(Context.SECURITY_AUTHENTICATION, DIGEST_MD5_AUTHENTICATION);
		authEnvProperties.setProperty(Context.SECURITY_PRINCIPAL, queryUsername);
		authEnvProperties.setProperty(Context.SECURITY_CREDENTIALS, queryPassword);
		return authEnvProperties;
	}


	protected void applyUserAuthentication(LdapContext ctx, String username, String password) throws NamingException {
		ctx.addToEnvironment(Context.SECURITY_AUTHENTICATION, DIGEST_MD5_AUTHENTICATION);
		ctx.addToEnvironment(Context.SECURITY_PRINCIPAL, username);
		ctx.addToEnvironment(Context.SECURITY_CREDENTIALS, password);
	}


	protected String domainToSearchBase(String domainName) {
		StringBuilder searchBase = new StringBuilder();
		for (String domainPart : domainName.split("\\.")) {
			if (searchBase.length() > 0) searchBase.append(",");
			if (domainPart.length() > 0) searchBase.append("DC=").append(domainPart);
		}
		return searchBase.toString();
	}

	private void log(String message){
		//System.out.println("message = " + message);
	}

	private String getProperty(String key) {
		if (properties == null) return "";
		if (properties.getProperty(key) == null) {
			System.out.println("Property not found [" + key + "] in plugins.properties");
			return "";
		}
		else {
			return properties.getProperty(key);
		}
	}

}

