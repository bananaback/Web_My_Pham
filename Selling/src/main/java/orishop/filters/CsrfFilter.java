package orishop.filters;

import javax.servlet.*;
import javax.servlet.http.*;

import orishop.util.Email;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CsrfFilter implements Filter {
	private static final Logger LOGGER = Logger.getLogger(Email.class.getName());

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        // Only check POST requests
        if (httpRequest.getMethod().equalsIgnoreCase("POST")) {
            // Retrieve CSRF token from the session
            HttpSession session = httpRequest.getSession(false);
            if (session != null) {
                String sessionToken = (String) session.getAttribute("csrfToken");

                String rawToken = httpRequest.getParameter("csrfToken");
                // Retrieve CSRF token from the request and sanitize it
                if (rawToken != null) {
                    String requestToken = sanitizeCSRFToken(rawToken);
                     // Compare tokens
                    if (sessionToken == null || !sessionToken.equals(requestToken)) {
                        LOGGER.log(Level.INFO, "request token:" + requestToken);
                        LOGGER.log(Level.INFO, "session token:" + sessionToken);

                        // Token mismatch, reject the request
                        httpResponse.sendRedirect(httpRequest.getContextPath() + "/views/web/csrf-error.jsp");
                        return;
                    }
                } else {
                    httpResponse.sendRedirect(httpRequest.getContextPath() + "/views/web/csrf-error.jsp");
                    return;
                }
               
            } else {
                // Session not found, reject the request
                httpResponse.sendError(HttpServletResponse.SC_FORBIDDEN, "Session Not Found");
                return;
            }
        }

        // Continue the filter chain for other requests or if the CSRF check passed
        chain.doFilter(request, response);
    }
    
    // Method to sanitize the CSRF token to prevent XSLT injection
    private String sanitizeCSRFToken(String token) {
        // Remove any XML tags and special characters that could be part of an XSLT injection attack
        return token.replaceAll("<[^>]*>", "").trim();
    }
}
