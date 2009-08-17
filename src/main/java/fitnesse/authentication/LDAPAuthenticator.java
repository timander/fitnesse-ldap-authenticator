package fitnesse.authentication;

import com.sun.jndi.ldap.LdapCtxFactory;
import javax.naming.AuthenticationException;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import java.util.Hashtable;
import java.util.Properties;


@SuppressWarnings({"ProtectedField"})
public class LDAPAuthenticator extends Authenticator {

    protected Properties properties;
    protected InitialDirContextFactory initialDirContextFactory = new InitialDirContextFactory();

    @SuppressWarnings({"AssignmentToCollectionOrArrayFieldFromParameter"})
    public LDAPAuthenticator(Properties properties) {
        this.properties = properties;
    }

    @SuppressWarnings({"UseOfObsoleteCollectionType", "unchecked", "RawUseOfParameterizedType", "CallToPrintStackTrace"})
    @Override
    public boolean isAuthenticated(String username, String password) throws Exception {
        if (username == null || password == null) {
            return false;
        }

        String searchBase = getProperty("ldap.search.base");
        String ldapURL = getProperty("ldap.server.url") + "/" + searchBase;
        String usernameAttribute = getProperty("ldap.username.attribute");
        String principal = usernameAttribute + "=" + username + "," + searchBase + "?" + usernameAttribute + "?sub?(objectClass=*)";

        System.out.println("LDAPAuthenticator.isAuthenticated");
        System.out.println("principal = " + principal);

        Hashtable authEnv = new Hashtable(11);
        authEnv.put(Context.INITIAL_CONTEXT_FACTORY, LdapCtxFactory.class.getName());
        authEnv.put(Context.PROVIDER_URL, ldapURL);
        authEnv.put(Context.SECURITY_AUTHENTICATION, "simple");
        authEnv.put(Context.SECURITY_PRINCIPAL, principal);
        authEnv.put(Context.SECURITY_CREDENTIALS, password);

        try {
            DirContext authContext = initialDirContextFactory.create(authEnv);
            return authContext != null;
        }
        catch (AuthenticationException ae) {
            ae.printStackTrace();
        }
        catch (NamingException ne) {
            ne.printStackTrace();
        }

        return false;
    }

    private String getProperty(String key) {
        if (properties.getProperty(key) == null) {
            System.out.println("Property not found [" + key + "] in plugins.properties");
            return "";
        }
        else {
            return properties.getProperty(key);
        }
    }

}

