package fitnesse.authentication;

import javax.naming.AuthenticationException;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapContext;
import java.util.Properties;


public class LDAPAuthenticator extends Authenticator {

	protected Properties properties;
	protected LdapContextFactory ldapContextFactory = new LdapContextFactory();
	private static final String DIGEST_MD5_AUTHENTICATION = "DIGEST-MD5";


	public LDAPAuthenticator(Properties properties) {
		this.properties = properties;
	}


	public boolean isAuthenticated(String username, String password) {
		if (username == null || password == null) return false;

		String ldapUrl = ldapUrl();

		log("Authenticating " + username + " through " + ldapUrl);

		boolean authenticated = false;
		LdapContext context = null;
		try {
			Properties props = setupAuthorizedEnv();
			context = ldapContextFactory.create(ldapUrl, props);
			log("Authentication succeeded for query user");

            applyUserAuthentication(context, username, password);

            String userPrincipalName = username + "@" + domainName();

            String ldapQuery = "(&(" + usernameAttribute() + "=" + username + ")(objectClass=user)" +
                            "(userPrincipalName=" + userPrincipalName + ")" + securityGroupFilter() + ")";
            log(ldapQuery);

            SearchControls controls = new SearchControls();
            controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            NamingEnumeration<SearchResult> searchResults = context.search(searchBase(), ldapQuery, controls);

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
			try {
				if (context != null) context.close();
			}
			catch(NamingException e) {
				log( "Context failed to close: " + e);
			}
		}
		return authenticated;
	}

    private String usernameAttribute() {
        return getProperty("ldap.username.attribute");
    }

    private String ldapUrl() {
        String serverName = getProperty("ldap.server.name");
        return "ldaps://" + serverName + "." + domainName() + '/';
    }

    private String domainName() {
        return getProperty("ldap.domain.name");
    }

    private String searchBase() {
        return domainToSearchBase(domainName());
    }

    private String securityGroupFilter() {
        String securityGroup = getProperty("ldap.security.group");
        String searchBase = searchBase();
        return isEmpty(securityGroup) ? "" : "(memberOf=CN=" + securityGroup + ",OU=Security Groups," + searchBase + "))";
    }

    private boolean isEmpty(String value) {
        return value == null || value.length() == 0;
    }

    private Properties setupAuthorizedEnv() {
        String queryUsername = getProperty("ldap.queryuser.username");
        String queryPassword = getProperty("ldap.queryuser.password");
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
		if (isEmpty(properties.getProperty(key))) {
			log("Property not found [" + key + "] in plugins.properties");
			return "";
		}
		else {
			return properties.getProperty(key);
		}
	}

}

