package fitnesse.authentication;

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

    @SuppressWarnings({"UseOfObsoleteCollectionType", "unchecked", "RawUseOfParameterizedType"})
    @Override
    public boolean isAuthenticated(String username, String password) throws Exception {
        if (username == null || password == null) {
            return false;
        }

        Hashtable authEnv = new Hashtable(11);
        String base = "ou=People,dc=example,dc=com";
        String dn = "uid=" + username + "," + base;
        String ldapURL = "ldap://ldap.example.com:389";

        authEnv.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        authEnv.put(Context.PROVIDER_URL, ldapURL);
        authEnv.put(Context.SECURITY_AUTHENTICATION, "simple");
        authEnv.put(Context.SECURITY_PRINCIPAL, dn);
        authEnv.put(Context.SECURITY_CREDENTIALS, password);

        try {
            DirContext authContext = initialDirContextFactory.create(authEnv);
            return authContext != null;
        }
        catch (AuthenticationException ae) {
            ae.printStackTrace();
            //throw new RuntimeException("Authentication failed!", ae);
        }
        catch (NamingException ne) {
            //throw new RuntimeException("Something went wrong!", ne);
            ne.printStackTrace();
        }

        return false;
    }

}

