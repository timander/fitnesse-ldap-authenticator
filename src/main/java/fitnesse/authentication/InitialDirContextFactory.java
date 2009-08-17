package fitnesse.authentication;

import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.util.Hashtable;


public class InitialDirContextFactory {

    public DirContext create(Hashtable env) throws NamingException {
        return new InitialDirContext(env);
    }

}
