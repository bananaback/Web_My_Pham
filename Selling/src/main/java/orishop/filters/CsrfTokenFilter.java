package orishop.filters;

import java.io.IOException;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import orishop.util.Email;

public class CsrfTokenFilter implements Filter {
	private static final Logger LOGGER = Logger.getLogger(Email.class.getName());

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        // Get the session or create a new one if it doesn't exist
        HttpSession session = request.getSession(true);

        // Generate CSRF token if not already present in the session
        if (session.getAttribute("csrfToken") == null) {
            String csrfToken = UUID.randomUUID().toString(); // Generate a random UUID as CSRF token
            session.setAttribute("csrfToken", csrfToken);
            LOGGER.log(Level.INFO, "Current token:" + csrfToken);
        } else {
            LOGGER.log(Level.INFO, "Current token:" + session.getAttribute("csrfToken"));

        }



        // Proceed with the filter chain
        filterChain.doFilter(request, response);
    }

}
