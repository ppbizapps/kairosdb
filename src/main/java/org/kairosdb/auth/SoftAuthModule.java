package org.kairosdb.auth;

import org.eclipse.jetty.jaas.callback.ObjectCallback;
import org.eclipse.jetty.jaas.spi.UserInfo;
import org.eclipse.jetty.util.log.Log;
import org.eclipse.jetty.util.log.Logger;
import org.eclipse.jetty.util.security.Credential;

import javax.security.auth.Subject;
import javax.security.auth.callback.*;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;
import java.io.IOException;
import java.util.Map;

public class SoftAuthModule  extends org.eclipse.jetty.jaas.spi.AbstractLoginModule
{
    private static final Logger LOG = Log.getLogger(SoftAuthModule.class);
    private CallbackHandler callbackHandler;
    private Subject subject;

    @Override
    public UserInfo getUserInfo(String username) throws Exception {
        Credential credential = Credential.getCredential("dummy");
        return new UserInfo(username,credential);
    }

    public UserInfo getUserInfo(String username, Object password) throws Exception {
        LOG.info("UserInfo");
        Credential credential = Credential.getCredential((String) password);
        return new UserInfo(username,credential);
    }

    @Override
    public boolean login() throws LoginException
    {
        try
        {
            if (super.isIgnored())
                return false;

            if (callbackHandler == null)
                throw new LoginException ("No callback handler");

            Callback[] callbacks = configureCallbacks();
            callbackHandler.handle(callbacks);

            String webUserName = ((NameCallback)callbacks[0]).getName();
            Object webCredential = null;

            webCredential = ((ObjectCallback)callbacks[1]).getObject(); //first check if ObjectCallback has the credential
            if (webCredential == null)
                webCredential = ((PasswordCallback)callbacks[2]).getPassword(); //use standard PasswordCallback

            if ((webUserName == null) || (webCredential == null))
            {
                webUserName = "SoftAuthFail";
                webCredential = "SAFPass";
                super.setAuthenticated(false);
            }

            UserInfo userInfo = getUserInfo(webUserName,webCredential);

            if (userInfo == null)
            {
                super.setAuthenticated(false);
                throw new FailedLoginException();
            }

            super.setCurrentUser(new JAASUserInfo(userInfo));
            super.setAuthenticated(super.getCurrentUser().checkCredential(webCredential));

            if (super.isAuthenticated())
            {
                super.getCurrentUser().fetchRoles();
                return true;
            }
            else
                throw new FailedLoginException();
        }
        catch (IOException e)
        {
            throw new LoginException (e.toString());
        }
        catch (UnsupportedCallbackException e)
        {
            throw new LoginException (e.toString());
        }
        catch (Exception e)
        {
            if (e instanceof LoginException)
                throw (LoginException)e;
            throw new LoginException (e.toString());
        }
    }

    /**
     * @see javax.security.auth.spi.LoginModule#initialize(javax.security.auth.Subject, javax.security.auth.callback.CallbackHandler, java.util.Map, java.util.Map)
     * @param subject the subject
     * @param callbackHandler the callback handler
     * @param sharedState the shared state map
     * @param options the option map
     */
    @Override
    public void initialize(Subject subject, CallbackHandler callbackHandler,
                           Map<String,?> sharedState, Map<String,?> options)
    {
        this.callbackHandler = callbackHandler;
        super.setCallbackHandler(callbackHandler);
        this.subject = subject;
        super.setSubject(subject);
    }
}
