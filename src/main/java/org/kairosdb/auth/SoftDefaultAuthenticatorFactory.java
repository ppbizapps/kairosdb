package org.kairosdb.auth;

import org.eclipse.jetty.security.Authenticator;
import org.eclipse.jetty.security.IdentityService;
import org.eclipse.jetty.security.LoginService;
import org.eclipse.jetty.security.authentication.*;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.util.security.Constraint;

import javax.servlet.ServletContext;

public class SoftDefaultAuthenticatorFactory extends org.eclipse.jetty.security.DefaultAuthenticatorFactory {

    @Override
    public Authenticator getAuthenticator(Server server, ServletContext context, Authenticator.AuthConfiguration configuration, IdentityService identityService, LoginService loginService)
    {
        String auth=configuration.getAuthMethod();
        Authenticator authenticator=null;

        if (auth==null || Constraint.__BASIC_AUTH.equalsIgnoreCase(auth))
            authenticator=new SoftBasicAuthenticator();
        else if (Constraint.__DIGEST_AUTH.equalsIgnoreCase(auth))
            authenticator=new DigestAuthenticator();
        else if (Constraint.__FORM_AUTH.equalsIgnoreCase(auth))
            authenticator=new FormAuthenticator();
        else if ( Constraint.__SPNEGO_AUTH.equalsIgnoreCase(auth) )
            authenticator = new SpnegoAuthenticator();
        else if ( Constraint.__NEGOTIATE_AUTH.equalsIgnoreCase(auth) ) // see Bug #377076
            authenticator = new SpnegoAuthenticator(Constraint.__NEGOTIATE_AUTH);
        if (Constraint.__CERT_AUTH.equalsIgnoreCase(auth)||Constraint.__CERT_AUTH2.equalsIgnoreCase(auth))
            authenticator=new ClientCertAuthenticator();

        return authenticator;
    }
}
