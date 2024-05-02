package orishop.filters;

import java.io.IOException;
import java.util.UUID;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

public class CsrfTokenFilter implements Filter {

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        // Get the session or create a new one if it doesn't exist
        HttpSession session = request.getSession();

        // Generate CSRF token if not already present in the session
        if (session.getAttribute("csrfToken") == null) {
            String csrfToken = UUID.randomUUID().toString(); // Generate a random UUID as CSRF token
            session.setAttribute("csrfToken", csrfToken);
        }

        // Proceed with the filter chain
        filterChain.doFilter(request, response);
    }

}
