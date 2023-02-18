package com.zzpzaf.restapidemo.Configuration;

import java.io.IOException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletResponse;


//@Component
public class CustomRequestHeaderTokenFilter extends UsernamePasswordAuthenticationFilter{

    /*
    * Taken from official documentation of the AbstractAuthenticationProcessingFilter:
    * 
    *
    * Authentication Process
    * The filter requires that you set the authenticationManager property. An AuthenticationManager 
    * is required to process the authentication request tokens created by implementing classes.
    * This filter will intercept a request and attempt to perform authentication from that request 
    * if the request matches the setRequiresAuthenticationRequestMatcher(RequestMatcher).
    * Authentication is performed by the attemptAuthentication method, which must be implemented by subclasses -> our class here.
    * 
    * Authentication Success
    * If authentication is successful, the resulting Authentication object will be placed into the SecurityContext for the current thread, 
    * which is guaranteed to have already been created by an earlier filter.
    * The configured AuthenticationSuccessHandler will then be called to take the redirect to the appropriate destination after a successful login. 
    * The default behaviour is implemented in a SavedRequestAwareAuthenticationSuccessHandler which will make use of any DefaultSavedRequest set 
    * by the ExceptionTranslationFilter and redirect the user to the URL contained therein. Otherwise it will redirect to the webapp root "/". 
    * You can customize this behaviour by injecting a differently configured instance of this class, or by using a different implementation.
    * See the successfulAuthentication(HttpServletRequest, HttpServletResponse, FilterChain, Authentication) method for more information.
    * 
    * Authentication Failure
    * If authentication fails, it will delegate to the configured AuthenticationFailureHandler to allow the failure information to be conveyed to the client. 
    * The default implementation is SimpleUrlAuthenticationFailureHandler , which sends a 401 error code to the client. It may also be configured with a failure URL as an alternative. Again you can inject whatever behaviour you require here.
    * 
    */


    private final Log logger = LogFactory.getLog(getClass());
    private AuthenticationManager authManager;

    public CustomRequestHeaderTokenFilter(AuthenticationManager authManager) {
        super(authManager);
        this.authManager = authManager;
    }




    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        /*
        * Invokes the requiresAuthentication() method to determine whether the request is for authentication and should be handled 
        * by this filter. If it is an authentication request, the attemptAuthentication will be invoked to perform the authentication. 
        * There are then three possible outcomes:
            1.	An Authentication object is returned. The configured SessionAuthenticationStrategy will be invoked (to handle any 
                session-related behavior such as creating a new session to protect against session-fixation attacks) followed by the 
                invocation of successfulAuthentication(HttpServletRequest, HttpServletResponse, FilterChain, Authentication) method
            2.	An AuthenticationException occurs during authentication. The unsuccessfulAuthentication method will be invoked
            3.	Null is returned, indicating that the authentication process is incomplete. The method will then return immediately, 
                assuming that the subclass has done any necessary work (such as redirects) to continue the authentication process. The assumption is that a later request will be received by this method where the returned Authentication object is not null.
        */


        logger.info("==>>  DoFilter ... Is Authentication required? ... ");
        
        //Here we will attempt JWT AUTHORIZATION
         

        //super.doFilter(request, response, chain); 

    }

    @Override
    public Authentication attemptAuthentication(jakarta.servlet.http.HttpServletRequest request,
                                                jakarta.servlet.http.HttpServletResponse response)
                                                throws AuthenticationException {

        /*
            Performs actual authentication.
            The implementation should do one of the following:
            1. Return a populated authentication token for the authenticated user, indicating successful authentication
            2. Return null, indicating that the authentication process is still in progress. 
               Before returning, the implementation should perform any additional work required to complete the process.
            3. Throw an AuthenticationException if the authentication process fails
            So, it should return either the authenticated user token, or null if authentication is incomplete.
         */

         logger.info("==>>  Attempting Authentication ... ");

         //Here we will attempt BASIC AUTHENTICATION
         
         return null;
    }


    @Override
    protected void successfulAuthentication(jakarta.servlet.http.HttpServletRequest request,
                                            jakarta.servlet.http.HttpServletResponse response,
                                            jakarta.servlet.FilterChain chain,
                                            Authentication authResult)
                                            throws IOException, jakarta.servlet.ServletException {
    
        /*
            Default behavior for successful authentication:
            Sets the successful Authentication object on the SecurityContextHolder
            Informs the configured RememberMeServices of the successful login
            Fires an InteractiveAuthenticationSuccessEvent via the configured ApplicationEventPublisher
            Delegates additional behavior to the AuthenticationSuccessHandler.
            Subclasses can override this method to continue the FilterChain after successful authentication.
         */

        logger.info("==>> SUCCESSFUL Authentication!  " + authResult.toString());

        //Here we will respond with a valid JWT token as value of the WWW_Authenticate header



    }



    @Override
    protected void  unsuccessfulAuthentication(jakarta.servlet.http.HttpServletRequest request, 
                                               jakarta.servlet.http.HttpServletResponse response, 
                                               AuthenticationException failed) 
                                               throws IOException, jakarta.servlet.ServletException {

        /* 
            Default behaviour for unsuccessful authentication:
            Clears the SecurityContextHolder
            Stores the exception in the session (if it exists or allowSessionCreation is set to true)
            Informs the configured RememberMeServices of the failed login
            Delegates additional behaviour to the AuthenticationFailureHandler.
        
            Handle here an unsuccessful authentication, so you can set necessary response headers, 
            content-type, or set the response status code and even  modify/add some JSON body to 
            the response send back to the client
        */          

        logger.info("==>> UN-SUCCESSFUL Authentication! " + failed.getMessage());

        //Here we will respond with ERROR Messages. For instance: 
        response.setHeader("WWW-Authenticate", "Basic realm=\"Access to /signin authentication endpoint\"");
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.getWriter().write("{ \"Error\": \"" + failed.getMessage()  +  ".\" }");

    }
    
}
