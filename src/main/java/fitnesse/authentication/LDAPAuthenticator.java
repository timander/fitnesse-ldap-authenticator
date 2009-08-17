package fitnesse.authentication;

import java.util.Properties;

public class LDAPAuthenticator extends Authenticator {

    public LDAPAuthenticator(Properties properties) {
    }

    @Override
    public boolean isAuthenticated(String username, String password) throws Exception {
        if (username == null || password == null) {
            return false;
        }
        return username.equals(password);
    }
}
