package orishop.filters;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

public class AuthenticationFilter implements Filter {

    private final String[] permittedURLs = {"/web/login", "/web/register", "/web/forgotpass", "/web/waiting", "/web/VerifyCode"};

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        // Get the requested URL
        String requestURL = request.getRequestURI();

        // Check if the requested URL is in the list of permitted URLs
        boolean isPermitted = false;
        for (String permittedURL : permittedURLs) {
            if (requestURL.endsWith(permittedURL)) {
                isPermitted = true;
                break;
            }
        }

        // If the requested URL is permitted, allow access without authentication
        if (isPermitted) {
            filterChain.doFilter(request, response);
            return;
        }

        // Get the session
        HttpSession session = request.getSession(false);

        // Check if "account" session attribute exists
        if (session != null && session.getAttribute("account") != null) {
            // User is authenticated, allow access to the requested resource
            filterChain.doFilter(request, response);
        } else {
            // User is not authenticated, redirect to the login page
            response.sendRedirect(request.getContextPath() + "/web/login");
        }
    }
}