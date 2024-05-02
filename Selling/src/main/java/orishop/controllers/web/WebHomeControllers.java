package orishop.controllers.web;

import java.io.IOException;
import java.io.PrintWriter;
import java.security.SecureRandom;
import java.util.Base64;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import orishop.models.AccountModels;
import orishop.models.RoleEnum;
import orishop.services.AccountServiceImpl;
import orishop.services.IAccountService;
import orishop.util.Constant;
import orishop.util.Email;
import orishop.util.InputSanitizer;

@WebServlet(urlPatterns = { "/web/login", "/web/register", "/web/forgotpass", "/web/waiting", "/web/VerifyCode",
		"/web/logout" })

public class WebHomeControllers extends HttpServlet {
	private static final long serialVersionUID = 1L;

	IAccountService accountService = new AccountServiceImpl();

	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {

		String url = req.getRequestURI().toString();

		// Add SameSite attribute to JSESSIONID cookie
		String sameSite = "Strict"; // You can set this to "Lax" if needed
		String cookieHeader = "JSESSIONID=" + req.getSession().getId() + "; Path=/Selling; HttpOnly; Secure; SameSite=" + sameSite;
		resp.setHeader("Set-Cookie", cookieHeader);


		if (url.contains("web/register")) {

			// Generate a random nonce
			SecureRandom random = new SecureRandom();
			byte[] nonceBytes = new byte[16]; // 128 bits
			random.nextBytes(nonceBytes);
			String nonce = Base64.getEncoder().encodeToString(nonceBytes);

			// Set the CSP header with the nonce and other directives
			String cspHeader = "script-src 'nonce-" + nonce + "' 'strict-dynamic'; " +
			"object-src 'none'; " +
			"base-uri 'none'; " +
			"frame-ancestors 'none'; " +
			"form-action 'self'; " +
			"style-src 'self'; " +
			"img-src 'self'; " +
			"connect-src 'self'; " +
			"font-src 'self'; " +
			"media-src 'self'; " +
			"manifest-src 'self'; " +
			"frame-src 'none';";

			resp.setHeader("Content-Security-Policy", cspHeader);
			req.setAttribute("nonce", nonce);

			req.getRequestDispatcher("/views/web/register.jsp").forward(req, resp);
		} else if (url.contains("web/VerifyCode")) {
			req.getRequestDispatcher("/views/web/verify.jsp").forward(req, resp);
		} else if (url.contains("web/login")) {
			getLogin(req, resp);
		} else if (url.contains("web/forgotpass")) {
			req.getRequestDispatcher("/views/web/forgotpassword.jsp").forward(req, resp);
		} else if (url.contains("web/waiting")) {
			getWaiting(req, resp);
		} else if (url.contains("web/logout")) {
			getLogout(req, resp);
		}

	}

	 private void getLogout(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        HttpSession session = req.getSession();
        session.removeAttribute("account");

        Cookie[] cookies = req.getCookies();

        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (Constant.COOKIE_REMEBER.equals(cookie.getName())) {
                    // Sanitize the cookie value to remove potential CRLF characters
                    String sanitizedValue = InputSanitizer.sanitizeInput(cookie.getValue());
                    cookie.setValue(sanitizedValue);

                    // Add the cookie with the sanitized value
                    cookie.setMaxAge(0);
                    resp.addCookie(cookie);
                }
            }
        }

        resp.sendRedirect(req.getContextPath() + "/user/home");
    }

	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		String url = req.getRequestURI().toString();
		if (url.contains("web/register")) {
			postRegister(req, resp);
		} else if (url.contains("web/login")) {
			postLogin(req, resp);
		} else if (url.contains("web/forgotpass")) {
			postForgotPassword(req, resp);
		} else if (url.contains("web/VerifyCode")) {
			postVerifyCode(req, resp);
		}
	}

	private void postVerifyCode(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		resp.setContentType("text/html; charset=UTF-8");
		try (PrintWriter out = resp.getWriter()) {

			// truy cập session
			HttpSession session = req.getSession();
			AccountModels user = (AccountModels) session.getAttribute("account");
			String code = req.getParameter("authcode");

			if (code.equals(user.getCode())) {
				user.setMail(user.getMail());
				user.setStatus(1);

				accountService.updatestatus(user);
				req.setAttribute("message", "Kích hoạt tài khoản thành công!");
				req.getRequestDispatcher("/views/web/login.jsp").forward(req, resp);
			} else {
				req.setAttribute("error", "Sai mã kích hoạt, vui lòng kiểm tra lại!!!");
				req.getRequestDispatcher("/views/web/verify.jsp").forward(req, resp);
			}
		} catch (Exception e) {
			e.getStackTrace();
		}
	}
	
	private void saveRememberMe(HttpServletResponse resp, String username) {
        // Sanitize the username parameter to remove potential CRLF characters
        String sanitizedUsername = InputSanitizer.sanitizeInput(username);

        String cookieValue = sanitizedUsername;
        String cookieName = Constant.COOKIE_REMEBER;
        String cookiePath = "/Selling"; // Specify the path for the cookie
        int maxAgeInSeconds = 30 * 60; // 30 minutes

        String cookieHeader = String.format("%s=%s; Path=%s; Max-Age=%d; HttpOnly; SameSite=Strict; Secure", cookieName, cookieValue, cookiePath, maxAgeInSeconds);
        resp.addHeader("Set-Cookie", cookieHeader);
    }
	

	private void postForgotPassword(HttpServletRequest req, HttpServletResponse resp)
			throws ServletException, IOException {
		resp.setContentType("text/html");
		resp.setCharacterEncoding("UTF-8");
		req.setCharacterEncoding("UTF-8");

		String username = req.getParameter("username");
		String email = req.getParameter("email");
		AccountModels user = accountService.findOne(username);
		if (user.getUsername() != null && user.getMail() != null) {
			if (user.getMail().equals(email) && user.getUsername().equals(username)) {
				Email sm = new Email();

				boolean test = sm.EmailSend(user);

				if (test) {
					req.setAttribute("message", "Vui lòng kiểm tra Email để nhận mật khẩu");
					req.getRequestDispatcher("/views/web/login.jsp").forward(req, resp);
				} else {
					req.setAttribute("error", "Lỗi gửi mail");
					req.getRequestDispatcher("/views/web/login.jsp").forward(req, resp);
				}
			} else {
				req.setAttribute("error", "username hoặc email không tồn tại trong hệ thống!");
				req.getRequestDispatcher("/views/web/forgotpassword.jsp").forward(req, resp);
				return;
			}
		} else {
			req.setAttribute("error", "username hoặc email không tồn tại trong hệ thống!");
			req.getRequestDispatcher("/views/web/forgotpassword.jsp").forward(req, resp);
		}
	}

	private void getLogin(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		// Generate a random nonce
		SecureRandom random = new SecureRandom();
		byte[] nonceBytes = new byte[16]; // 128 bits
		random.nextBytes(nonceBytes);
		String nonce = Base64.getEncoder().encodeToString(nonceBytes);
	
		// Set the CSP header with the nonce and other directives
		String cspHeader = "script-src 'nonce-" + nonce + "' 'strict-dynamic'; " +
		"object-src 'none'; " +
		"base-uri 'none'; " +
		"frame-ancestors 'none'; " +
		"form-action 'self'; " +
		"style-src 'self' https://fonts.googleapis.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com/; " + // Allow styles from 'self' and Google Fonts, cdn, cloudflare
		"img-src 'self'; " +
		"connect-src 'self'; " +
		"font-src 'self' https://fonts.gstatic.com; " + // Allow fonts from 'self' and Google Fonts
		"media-src 'self'; " +
		"manifest-src 'self'; " +
		"frame-src 'none';";
	
		resp.setHeader("Content-Security-Policy", cspHeader);
		resp.setHeader("X-Content-Type-Options", "nosniff");
		//resp.setContentType("text/html;charset=UTF-8");
	
		// Add Strict-Transport-Security header
		resp.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
	
		// Check session
		HttpSession session = req.getSession(false);
		if (session != null && session.getAttribute("account") != null) {
			resp.sendRedirect(req.getContextPath() + "/web/waiting");
			return;
		}
	
		// Check cookie
		Cookie[] cookies = req.getCookies();
		if (cookies != null) {
			for (Cookie cookie : cookies) {
				if (cookie.getName().equals("username")) {
					session = req.getSession(true);
					session.setAttribute("username", cookie.getValue());
					resp.sendRedirect(req.getContextPath() + "/waiting");
					return;
				}
			}
		}
	
		// Set the nonce attribute for the view
		req.setAttribute("nonce", nonce);
		req.getRequestDispatcher("/views/web/login.jsp").forward(req, resp);
	}
	
	

	private void postLogin(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		resp.setCharacterEncoding("UTF-8");
		//resp.setContentType("text/html;charset=UTF-8");

		// Check if the request contains XML content
		if (req.getContentType() != null && req.getContentType().toLowerCase().contains("xml")) {
			resp.setStatus(HttpServletResponse.SC_UNSUPPORTED_MEDIA_TYPE);
			resp.getWriter().println("XML content is not supported for login.");
			return;
		}

		// Generate a random nonce
		SecureRandom random = new SecureRandom();
		byte[] nonceBytes = new byte[16]; // 128 bits
		random.nextBytes(nonceBytes);
		String nonce = Base64.getEncoder().encodeToString(nonceBytes);

		// Set the CSP header with the nonce and other directives
		String cspHeader = "script-src 'nonce-" + nonce + "' 'strict-dynamic'; " +
		"object-src 'none'; " +
		"base-uri 'none'; " +
		"frame-ancestors 'none'; " +
		"form-action 'self'; " +
		"style-src 'self' https://fonts.googleapis.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com/; " + // Allow styles from 'self' and Google Fonts, cdn, cloudflare
		"img-src 'self'; " +
		"connect-src 'self'; " +
		"font-src 'self' https://fonts.gstatic.com; " + // Allow fonts from 'self' and Google Fonts
		"media-src 'self'; " +
		"manifest-src 'self'; " +
		"frame-src 'none';";

		resp.setHeader("Content-Security-Policy", cspHeader);
		resp.setHeader("X-Content-Type-Options", "nosniff");
		// Add Strict-Transport-Security header
		resp.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
	


		req.setCharacterEncoding("UTF-8");
		String username = req.getParameter("username");
		String password = req.getParameter("password");
		boolean isRememberMe = false;
		String remember = req.getParameter("remember");

		if ("on".equals(remember)) {
			isRememberMe = true;
		}
		String alertMsg = "";
		if (username == null || password == null || username.isEmpty() || password.isEmpty()) {
			alertMsg = "Tài khoản hoặc mật khẩu không đúng";
			req.setAttribute("error", alertMsg);
			req.getRequestDispatcher("/views/web/login.jsp").forward(req, resp);
			return;
		}

		AccountModels user = accountService.login(username, password);
		if (user != null) {
			if (user.getStatus() == 1) {

				// tạo session
				HttpSession session = req.getSession(true);
				session.setAttribute("account", user);

				if (isRememberMe) {
					saveRememberMe(resp, username);
				}

				resp.sendRedirect(req.getContextPath() + "/web/waiting");

			} else {
				alertMsg = "Tài khoản đã bị khóa, liên hệ  Admin nhé";
				req.setAttribute("error", alertMsg);
				req.setAttribute("nonce", nonce);

				req.getRequestDispatcher("/views/web/login.jsp").forward(req, resp);
			}

		} else {
			alertMsg = "Tài khoản hoặc mật khẩu không đúng";
			req.setAttribute("error", alertMsg);
			req.setAttribute("nonce", nonce);

			req.getRequestDispatcher("/views/web/login.jsp").forward(req, resp);

		}
	}

	private void getWaiting(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {

		// kiem tra session
		HttpSession session = req.getSession();
		if (session != null && session.getAttribute("account") != null) {
			AccountModels u = (AccountModels) session.getAttribute("account");
			req.setAttribute("username", u.getUsername());
			if (u.getRoleID() == RoleEnum.USER.getRoleId()) {
				resp.sendRedirect(req.getContextPath() + "/user/home");
			} else if (u.getRoleID() == RoleEnum.ADMIN.getRoleId()) {
				resp.sendRedirect(req.getContextPath() + "/admin/home");
			} else if (u.getRoleID() == RoleEnum.SELLER.getRoleId()) {
				resp.sendRedirect(req.getContextPath() + "/seller/home");
			} else if (u.getRoleID() == RoleEnum.SHIPPER.getRoleId()) {
				resp.sendRedirect(req.getContextPath() + "/shipper/home");
			}
		} else {
			resp.sendRedirect(req.getContextPath() + "/web/login");
		}
	}

	private void postRegister(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		resp.setContentType("text/html");
		resp.setCharacterEncoding("UTF-8");


		// Generate a random nonce
		SecureRandom random = new SecureRandom();
		byte[] nonceBytes = new byte[16]; // 128 bits
		random.nextBytes(nonceBytes);
		String nonce = Base64.getEncoder().encodeToString(nonceBytes);
		
		// Set the CSP header with the nonce and other directives
		String cspHeader = "script-src 'nonce-" + nonce + "' 'strict-dynamic'; " +
		"object-src 'none'; " +
		"base-uri 'none'; " +
		"frame-ancestors 'none'; " +
		"form-action 'self'; " +
		"style-src 'self'; " +
		"img-src 'self'; " +
		"connect-src 'self'; " +
		"font-src 'self'; " +
		"media-src 'self'; " +
		"manifest-src 'self'; " +
		"frame-src 'none';";

		resp.setHeader("Content-Security-Policy", cspHeader);
		req.setAttribute("nonce", nonce);

		req.setCharacterEncoding("UTF-8");
		String username = req.getParameter("username");
		String password = req.getParameter("password");
		String passwordConfirm = req.getParameter("passwordConfirm");
		String email = req.getParameter("email");

		if (password.equals(passwordConfirm)) {
			String alertMsg = "";
			if (accountService.checkExistEmail(email)) {
				alertMsg = "Email đã tồn tại";
				req.setAttribute("error", alertMsg);
				req.getRequestDispatcher("/views/web/register.jsp").forward(req, resp);
			} else if (accountService.checkExistUsername(username)) {
				alertMsg = "Tài khoản đã tồn tại";
				req.setAttribute("error", alertMsg);
				req.getRequestDispatcher("/views/web/register.jsp").forward(req, resp);
			} else {
				Email sm = new Email();
				// get the 6-digit code
				String code = sm.getRandom();
				AccountModels user = new AccountModels(username, email, code);
				boolean test = sm.sendEmail(user);

				if (test) {
					HttpSession session = req.getSession();
					session.setAttribute("account", user);

					boolean isSuccess = accountService.register(username, password, email, code);

					if (isSuccess) {
						resp.sendRedirect(req.getContextPath() + "/web/VerifyCode");

					} else {
						alertMsg = "Lỗi hệ thống!";
						req.setAttribute("error", alertMsg);
						req.getRequestDispatcher("/views/web/register.jsp").forward(req, resp);
					}
				} else {
					alertMsg = "Lỗi khi gửi mail!!!!!!!!!!!!!!";
					req.setAttribute("error", alertMsg);
					req.getRequestDispatcher("/views/web/register.jsp").forward(req, resp);

				}
			}
		} else {
			String alertMsg = "PasswordConfirm khác password";
			req.setAttribute("error", alertMsg);
			req.getRequestDispatcher("/views/web/register.jsp").forward(req, resp);
		}
	}

}
