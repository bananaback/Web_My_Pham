package orishop.filters;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import orishop.models.AccountModels;
import orishop.models.RoleEnum;

import java.io.IOException;

public class AuthorizationFilter implements Filter {

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        // Get the session
        HttpSession session = request.getSession(false);

        // Check if "account" session attribute exists and user has appropriate role
        if (session != null && session.getAttribute("account") != null) {
            AccountModels user = (AccountModels) session.getAttribute("account");
            String requestURI = request.getRequestURI();

            // Check user's role and restrict access accordingly
            if (requestURI.contains("/admin/") && user.getRoleID() != RoleEnum.ADMIN.getRoleId()) {
                // User does not have admin role, redirect to unauthorized page or display an error message
                response.sendRedirect(request.getContextPath() + "/views/unauthorized.jsp");
                return;
            } else if (requestURI.contains("/seller/") && user.getRoleID() != RoleEnum.SELLER.getRoleId()) {
                // User does not have seller role, redirect to unauthorized page or display an error message
                response.sendRedirect(request.getContextPath() + "/views/unauthorized.jsp");
                return;
            } else if (requestURI.contains("/shipper/") && user.getRoleID() != RoleEnum.SHIPPER.getRoleId()) {
                // User does not have shipper role, redirect to unauthorized page or display an error message
                response.sendRedirect(request.getContextPath() + "/views/unauthorized.jsp");
                return;
            }
        } else {
            // User is not authenticated, redirect to the login page or display an error message
            response.sendRedirect(request.getContextPath() + "/web/login");
            return;
        }

        // If the user has the appropriate role, continue the filter chain
        filterChain.doFilter(request, response);
    }
}
