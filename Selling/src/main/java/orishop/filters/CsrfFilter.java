package orishop.filters;

import javax.servlet.*;
import javax.servlet.http.*;
import java.io.IOException;

public class CsrfFilter implements Filter {

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

                // Retrieve CSRF token from the request
                String requestToken = httpRequest.getParameter("csrfToken");

                // Compare tokens
                if (sessionToken == null || !sessionToken.equals(requestToken)) {
                    // Token mismatch, reject the request
                    httpResponse.sendError(HttpServletResponse.SC_FORBIDDEN, "CSRF Token Validation Failed" + requestToken + " - " + sessionToken);
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
}
