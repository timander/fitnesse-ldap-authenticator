package fitnesse.authentication;

import com.sun.jndi.ldap.LdapCtxFactory;

import javax.naming.NamingException;
import javax.naming.ldap.LdapContext;
import java.util.Properties;


public class LdapContextFactory {
    public LdapContext create(String ldapURL, Properties env) throws NamingException {
	    return (LdapContext) LdapCtxFactory.getLdapCtxInstance(ldapURL, env);
    }
}
