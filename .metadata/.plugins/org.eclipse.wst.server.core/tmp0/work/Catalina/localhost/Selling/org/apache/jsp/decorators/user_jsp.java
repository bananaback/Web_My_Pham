/*
 * Generated by the Jasper component of Apache Tomcat
 * Version: Apache Tomcat/9.0.65
 * Generated at: 2023-12-05 07:23:15 UTC
 * Note: The last modified time of this file was set to
 *       the last modified time of the source file after
 *       generation to assist with modification tracking.
 */
package org.apache.jsp.decorators;

import javax.servlet.*;
import javax.servlet.http.*;
import javax.servlet.jsp.*;

public final class user_jsp extends org.apache.jasper.runtime.HttpJspBase
    implements org.apache.jasper.runtime.JspSourceDependent,
                 org.apache.jasper.runtime.JspSourceImports {

  private static final javax.servlet.jsp.JspFactory _jspxFactory =
          javax.servlet.jsp.JspFactory.getDefaultFactory();

  private static java.util.Map<java.lang.String,java.lang.Long> _jspx_dependants;

  static {
    _jspx_dependants = new java.util.HashMap<java.lang.String,java.lang.Long>(9);
    _jspx_dependants.put("jar:file:/C:/Users/Admin/Documents/LuanSu/CNTT/HK5/Web/Project/web/.metadata/.plugins/org.eclipse.wst.server.core/tmp0/wtpwebapps/Selling/WEB-INF/lib/jstl-1.2.jar!/META-INF/c.tld", Long.valueOf(1153359882000L));
    _jspx_dependants.put("/WEB-INF/lib/jstl-1.2.jar", Long.valueOf(1695140474521L));
    _jspx_dependants.put("/common/user/header.jsp", Long.valueOf(1701760708949L));
    _jspx_dependants.put("/common/taglist.jsp", Long.valueOf(1698300930250L));
    _jspx_dependants.put("jar:file:/C:/Users/Admin/Documents/LuanSu/CNTT/HK5/Web/Project/web/.metadata/.plugins/org.eclipse.wst.server.core/tmp0/wtpwebapps/Selling/WEB-INF/lib/jstl-1.2.jar!/META-INF/fmt-1_0-rt.tld", Long.valueOf(1153359882000L));
    _jspx_dependants.put("/WEB-INF/lib/sitemesh-2.4.2.jar", Long.valueOf(1695790380415L));
    _jspx_dependants.put("/common/user/footer.jsp", Long.valueOf(1701760708949L));
    _jspx_dependants.put("jar:file:/C:/Users/Admin/Documents/LuanSu/CNTT/HK5/Web/Project/web/.metadata/.plugins/org.eclipse.wst.server.core/tmp0/wtpwebapps/Selling/WEB-INF/lib/sitemesh-2.4.2.jar!/META-INF/sitemesh-decorator.tld", Long.valueOf(1123653092000L));
    _jspx_dependants.put("jar:file:/C:/Users/Admin/Documents/LuanSu/CNTT/HK5/Web/Project/web/.metadata/.plugins/org.eclipse.wst.server.core/tmp0/wtpwebapps/Selling/WEB-INF/lib/jstl-1.2.jar!/META-INF/fn.tld", Long.valueOf(1153359882000L));
  }

  private static final java.util.Set<java.lang.String> _jspx_imports_packages;

  private static final java.util.Set<java.lang.String> _jspx_imports_classes;

  static {
    _jspx_imports_packages = new java.util.HashSet<>();
    _jspx_imports_packages.add("javax.servlet");
    _jspx_imports_packages.add("javax.servlet.http");
    _jspx_imports_packages.add("javax.servlet.jsp");
    _jspx_imports_classes = null;
  }

  private org.apache.jasper.runtime.TagHandlerPool _005fjspx_005ftagPool_005fc_005furl_0026_005fvalue_005fnobody;
  private org.apache.jasper.runtime.TagHandlerPool _005fjspx_005ftagPool_005fdecorator_005fbody_005fnobody;

  private volatile javax.el.ExpressionFactory _el_expressionfactory;
  private volatile org.apache.tomcat.InstanceManager _jsp_instancemanager;

  public java.util.Map<java.lang.String,java.lang.Long> getDependants() {
    return _jspx_dependants;
  }

  public java.util.Set<java.lang.String> getPackageImports() {
    return _jspx_imports_packages;
  }

  public java.util.Set<java.lang.String> getClassImports() {
    return _jspx_imports_classes;
  }

  public javax.el.ExpressionFactory _jsp_getExpressionFactory() {
    if (_el_expressionfactory == null) {
      synchronized (this) {
        if (_el_expressionfactory == null) {
          _el_expressionfactory = _jspxFactory.getJspApplicationContext(getServletConfig().getServletContext()).getExpressionFactory();
        }
      }
    }
    return _el_expressionfactory;
  }

  public org.apache.tomcat.InstanceManager _jsp_getInstanceManager() {
    if (_jsp_instancemanager == null) {
      synchronized (this) {
        if (_jsp_instancemanager == null) {
          _jsp_instancemanager = org.apache.jasper.runtime.InstanceManagerFactory.getInstanceManager(getServletConfig());
        }
      }
    }
    return _jsp_instancemanager;
  }

  public void _jspInit() {
    _005fjspx_005ftagPool_005fc_005furl_0026_005fvalue_005fnobody = org.apache.jasper.runtime.TagHandlerPool.getTagHandlerPool(getServletConfig());
    _005fjspx_005ftagPool_005fdecorator_005fbody_005fnobody = org.apache.jasper.runtime.TagHandlerPool.getTagHandlerPool(getServletConfig());
  }

  public void _jspDestroy() {
    _005fjspx_005ftagPool_005fc_005furl_0026_005fvalue_005fnobody.release();
    _005fjspx_005ftagPool_005fdecorator_005fbody_005fnobody.release();
  }

  public void _jspService(final javax.servlet.http.HttpServletRequest request, final javax.servlet.http.HttpServletResponse response)
      throws java.io.IOException, javax.servlet.ServletException {

    if (!javax.servlet.DispatcherType.ERROR.equals(request.getDispatcherType())) {
      final java.lang.String _jspx_method = request.getMethod();
      if ("OPTIONS".equals(_jspx_method)) {
        response.setHeader("Allow","GET, HEAD, POST, OPTIONS");
        return;
      }
      if (!"GET".equals(_jspx_method) && !"POST".equals(_jspx_method) && !"HEAD".equals(_jspx_method)) {
        response.setHeader("Allow","GET, HEAD, POST, OPTIONS");
        response.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED, "JSPs only permit GET, POST or HEAD. Jasper also permits OPTIONS");
        return;
      }
    }

    final javax.servlet.jsp.PageContext pageContext;
    javax.servlet.http.HttpSession session = null;
    final javax.servlet.ServletContext application;
    final javax.servlet.ServletConfig config;
    javax.servlet.jsp.JspWriter out = null;
    final java.lang.Object page = this;
    javax.servlet.jsp.JspWriter _jspx_out = null;
    javax.servlet.jsp.PageContext _jspx_page_context = null;


    try {
      response.setContentType("text/html; charset=UTF-8");
      pageContext = _jspxFactory.getPageContext(this, request, response,
      			null, true, 8192, true);
      _jspx_page_context = pageContext;
      application = pageContext.getServletContext();
      config = pageContext.getServletConfig();
      session = pageContext.getSession();
      out = pageContext.getOut();
      _jspx_out = out;

      out.write('\r');
      out.write('\n');
      out.write(' ');
      out.write("\r\n");
      out.write("\r\n");
      out.write("\r\n");
      out.write("\r\n");
      out.write("\r\n");
      out.write("\r\n");
      out.write("\r\n");
      out.write("<!DOCTYPE html>\r\n");
      out.write("<html lang=\"fr\">\r\n");
      out.write("<head>\r\n");
      out.write("    <!-- Site meta -->\r\n");
      out.write("    <meta charset=\"utf-8\">\r\n");
      out.write("    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1, shrink-to-fit=no\">\r\n");
      out.write("    <title>Free Bootstrap 4 Ecommerce Template</title>\r\n");
      out.write("    <!-- CSS -->\r\n");
      out.write("    <link href=\"https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css\" rel=\"stylesheet\" type=\"text/css\">\r\n");
      out.write("    <link href=\"https://maxcdn.bootstrapcdn.com/font-awesome/4.7.0/css/font-awesome.min.css\" rel=\"stylesheet\" type=\"text/css\">\r\n");
      out.write("    <link href=\"https://fonts.googleapis.com/css?family=Open+Sans:400,300,600\" rel=\"stylesheet\" type=\"text/css\">\r\n");
      out.write("    <link href='");
      if (_jspx_meth_c_005furl_005f0(_jspx_page_context))
        return;
      out.write("' rel=\"stylesheet\" type=\"text/css\">\r\n");
      out.write("</head>\r\n");
      out.write("<body>\r\n");
      out.write("	");
      out.write("\r\n");
      out.write("\r\n");
      out.write(" ");
      out.write("\r\n");
      out.write("\r\n");
      out.write("\r\n");
      out.write("\r\n");
      out.write("\r\n");
      out.write("\r\n");
      out.write("\r\n");
      out.write("\r\n");
      out.write("<!DOCTYPE html>\r\n");
      out.write("<html>\r\n");
      out.write("<head>\r\n");
      out.write("<!-- Site meta -->\r\n");
      out.write("<meta charset=\"utf-8\">\r\n");
      out.write("<meta name=\"viewport\"\r\n");
      out.write("	content=\"width=device-width, initial-scale=1, shrink-to-fit=no\">\r\n");
      out.write("<title>Header</title>\r\n");
      out.write("<!-- Favicon-->\r\n");
      out.write("<link rel=\"icon\" type=\"image/x-icon\" href=\"assets/favicon.ico\" />\r\n");
      out.write("<!-- Google fonts-->\r\n");
      out.write("<link href=\"https://fonts.googleapis.com/css?family=Montserrat:400,700\"\r\n");
      out.write("	rel=\"stylesheet\" type=\"text/css\" />\r\n");
      out.write("<link\r\n");
      out.write("	href=\"https://fonts.googleapis.com/css?family=Lato:400,700,400italic,700italic\"\r\n");
      out.write("	rel=\"stylesheet\" type=\"text/css\" />\r\n");
      out.write("<link\r\n");
      out.write("	href=\"https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css\"\r\n");
      out.write("	rel=\"stylesheet\">\r\n");
      out.write("<link\r\n");
      out.write("	href=\"https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css\"\r\n");
      out.write("	rel=\"stylesheet\">\r\n");
      out.write("<!-- Core theme CSS (includes Bootstrap)-->\r\n");
      out.write("	<link href='");
      if (_jspx_meth_c_005furl_005f1(_jspx_page_context))
        return;
      out.write("'\r\n");
      out.write("		rel=\"stylesheet\" type=\"text/css\">\r\n");
      out.write("	<link href='");
      if (_jspx_meth_c_005furl_005f2(_jspx_page_context))
        return;
      out.write("' rel=\"stylesheet\"\r\n");
      out.write("		type=\"text/css\">\r\n");
      out.write("</head>\r\n");
      out.write("\r\n");
      out.write("<body>\r\n");
      out.write("	<nav class=\"navbar navbar-expand-xxl bg-body-tertiary\">\r\n");
      out.write("		<div class=\"container-fluid d-flex justify-content-between\">\r\n");
      out.write("			<div class=\"collapse\" id=\"navbarToggleExternalContent\"\r\n");
      out.write("				data-bs-theme=\"light\">\r\n");
      out.write("				<div class=\"bg-light p-4\">\r\n");
      out.write("					<h5 class=\"text-body-emphasis h4\">Collapsed content</h5>\r\n");
      out.write("					<span class=\"text-body-secondary\">Toggleable via the navbar\r\n");
      out.write("						brand.</span>\r\n");
      out.write("				</div>\r\n");
      out.write("			</div>\r\n");
      out.write("			<nav class=\"navbar navbar-light bg-light\">\r\n");
      out.write("				<div class=\"container-fluid\">\r\n");
      out.write("					<button class=\"navbar-toggler\" type=\"button\"\r\n");
      out.write("						data-bs-toggle=\"collapse\"\r\n");
      out.write("						data-bs-target=\"#navbarToggleExternalContent\"\r\n");
      out.write("						aria-controls=\"navbarToggleExternalContent\" aria-expanded=\"false\"\r\n");
      out.write("						aria-label=\"Toggle navigation\">\r\n");
      out.write("						<span class=\"navbar-toggler-icon\"></span>\r\n");
      out.write("					</button>\r\n");
      out.write("				</div>\r\n");
      out.write("			</nav>\r\n");
      out.write("			<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 139 31\"\r\n");
      out.write("				height=\"40\" width=\"80\" data-id=\"common\" class=\"appshell-fp-16d8r2m\">\r\n");
      out.write("				<path\r\n");
      out.write("					d=\"M57.98 28.94l-1.595-4.904h-.98L53.81 28.94l-1.593-4.91h-1.23l2.206 6.62h.98l1.716-4.66 1.59 4.66h.98l2.2-6.62h-1.22zM1.334 26.857h33.35v.98H1.334v-.98zm41.318-24.89h2.207v14.59h-2.21V1.967zm10.544 14.59h2.207v-6.13h7.602V8.343h-7.61V3.93h8.46V1.966h-10.66zM8.324 16.8c4.66 0 8.46-3.8 8.46-8.46 0-4.534-3.8-6.62-6.62-6.62-5.518 0-5.886 5.396-5.886 5.396h.13s.98-3.923 4.78-3.923c3.07 0 5.4 2.084 5.4 5.027 0 3.43-2.82 6.25-6.25 6.25-3.31 0-6.372-2.45-6.372-6.87 0-3.44 1.84-6.26 5.027-7.48V0C2.947.61.003 4.17.003 8.33c-.122 4.66 3.68 8.46 8.338 8.46zm36.78 10.056c-1.225-.245-1.593-.49-1.593-.98s.37-.737 1.11-.737c.62 0 1.23.24 1.72.61l.617-.85c-.613-.49-1.47-.86-2.33-.86-1.35 0-2.207.74-2.207 1.96s.73 1.6 2.2 1.96c1.22.25 1.47.49 1.47.98s-.49.86-1.1.86c-.86 0-1.47-.37-2.09-.86l-.74.86c.735.74 1.716 1.11 2.696 1.11 1.35 0 2.33-.73 2.33-1.96 0-1.35-.738-1.84-2.086-2.08zm-9.317-10.3l-4.414-5.884c2.207-.61 3.678-2.2 3.678-4.29 0-2.69-2.2-4.53-5.39-4.53h-6.38v14.59h2.2v-5.4h3.55l4.05 5.4 2.7.126zm-10.3-7.48V3.93h4.047c2.084 0 3.31.86 3.31 2.453s-1.35 2.575-3.31 2.575h-4.047zm40.706 18.76h3.31v-1.102h-3.31V25.14h3.678v-1.103h-4.78v6.498h4.78v-.98H66.2zM91.817 1.844l-6.62 14.713h2.33l1.715-3.8h7.11l1.595 3.8h2.452L93.78 1.844h-1.964zm-1.838 8.95l2.69-6.252 2.69 6.26h-5.4zm18.14-5.026l4.66 6.866.24.368.24-.36 4.536-6.86v10.79h2.207v-14.6h-2.084l-4.904 7.356-4.906-7.356h-2.08v14.59h2.085zm0 21.088h30.89v.98h-30.89v-.98zm22.19-12.383v-4.29h7.6V8.098h-7.6v-4.17h8.58v-1.96h-10.78v14.59h10.79V14.47zM98.93 28.57l-3.557-4.534H94.27v6.498h1.226v-4.536l3.55 4.536h.98v-6.498h-1.1zM72.936 1.968h-2.084v14.59h10.054v-2.084h-7.97zm13.12 25.87h3.31v-1.103h-3.31V25.14h3.677v-1.103H84.95v6.498h4.905v-.98h-3.81zm-9.197-3.8H74.4v6.497h2.453c2.083 0 3.432-1.47 3.432-3.31.122-1.717-1.35-3.188-3.434-3.188zm0 5.516h-1.35V25.14h1.35c1.35 0 2.2.98 2.2 2.206.12 1.226-.86 2.207-2.21 2.207z\"></path></svg>\r\n");
      out.write("			<form class=\"d-flex\" role=\"search\">\r\n");
      out.write("				<div style=\"display: flex-column; align-items: center;\">	\r\n");
      out.write("					<i class=\"fa-solid fa-magnifying-glass\" style=\" margin-right: 10px;\"></i>\r\n");
      out.write("					<input class=\"form-control me-2\" type=\"search\" placeholder=\"Search\"\r\n");
      out.write("						aria-label=\"Search\" style=\"width: 500px;\">\r\n");
      out.write("				</div>\r\n");
      out.write("			</form>\r\n");
      out.write("\r\n");
      out.write("			<span class=\"navbar-text\"> Đăng nhập</span> <span class=\"navbar-text\">\r\n");
      out.write("				Đăng ký</span> <i class=\"fa-solid fa-cart-shopping\"></i>\r\n");
      out.write("		</div>\r\n");
      out.write("	</nav>	\r\n");
      out.write("</body>\r\n");
      out.write("</html>");
      out.write("\r\n");
      out.write("	\r\n");
      out.write("	<div class=\"fluid-container\">\r\n");
      out.write("		");
      if (_jspx_meth_decorator_005fbody_005f0(_jspx_page_context))
        return;
      out.write("\r\n");
      out.write("	</div>\r\n");
      out.write("	\r\n");
      out.write("	");
      out.write("\r\n");
      out.write("	\r\n");
      out.write(" ");
      out.write("\r\n");
      out.write("\r\n");
      out.write("\r\n");
      out.write("\r\n");
      out.write("\r\n");
      out.write("\r\n");
      out.write("\r\n");
      out.write("\r\n");
      out.write("<!DOCTYPE html>\r\n");
      out.write("<html>\r\n");
      out.write("<head>\r\n");
      out.write("<!-- Site meta -->\r\n");
      out.write("<meta charset=\"utf-8\">\r\n");
      out.write("<meta name=\"viewport\"\r\n");
      out.write("	content=\"width=device-width, initial-scale=1, shrink-to-fit=no\">\r\n");
      out.write("<title>Footer</title>\r\n");
      out.write("<!-- Favicon-->\r\n");
      out.write("<link rel=\"icon\" type=\"image/x-icon\" href=\"assets/favicon.ico\" />\r\n");
      out.write("<!-- Google fonts-->\r\n");
      out.write("<link href=\"https://fonts.googleapis.com/css?family=Montserrat:400,700\"\r\n");
      out.write("	rel=\"stylesheet\" type=\"text/css\" />\r\n");
      out.write("<link\r\n");
      out.write("	href=\"https://fonts.googleapis.com/css?family=Lato:400,700,400italic,700italic\"\r\n");
      out.write("	rel=\"stylesheet\" type=\"text/css\" />\r\n");
      out.write("\r\n");
      out.write("\r\n");
      out.write("<link\r\n");
      out.write("	href=\"https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css\"\r\n");
      out.write("	rel=\"stylesheet\">\r\n");
      out.write("<link\r\n");
      out.write("	href=\"https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css\"\r\n");
      out.write("	rel=\"stylesheet\">\r\n");
      out.write("<!-- Core theme CSS (includes Bootstrap)-->\r\n");
      out.write("<link href='");
      if (_jspx_meth_c_005furl_005f3(_jspx_page_context))
        return;
      out.write("'\r\n");
      out.write("	rel=\"stylesheet\" type=\"text/css\">\r\n");
      out.write("<link href='");
      if (_jspx_meth_c_005furl_005f4(_jspx_page_context))
        return;
      out.write("' rel=\"stylesheet\"\r\n");
      out.write("	type=\"text/css\">\r\n");
      out.write("</head>\r\n");
      out.write("\r\n");
      out.write("<body>\r\n");
      out.write("	<nav class=\"navbar fixed-bottom bg-body-tertiary\">\r\n");
      out.write("		<div class=\"container mt-5 justify-content-center\">\r\n");
      out.write("			<div class=\"row\">\r\n");
      out.write("				<div class=\"col-sm-6 col-md-4 col-lg-3\">\r\n");
      out.write("					<h3>CHÍNH SÁCH & QUY ĐỊNH</h3>\r\n");
      out.write("					<p>Chính Sách & Quy Định Chung</p>\r\n");
      out.write("					<p>Chính sách bảo vệ dữ liệu cá nhân</p>\r\n");
      out.write("					<p>Quy Trình Đặt Sản Phẩm, Thanh Toán Và Giao Nhận Sản Phẩm</p>\r\n");
      out.write("					<p>Quy Trình Trả Lại, Mua Lại Sản Phẩm</p>\r\n");
      out.write("					<p>Chính sách vận chuyển - giao nhận</p>\r\n");
      out.write("					<p>Quy Định Về Phương Thức Thanh Toán</p>\r\n");
      out.write("				</div>\r\n");
      out.write("				<div class=\"col-sm-6 col-md-4 col-lg-3\">\r\n");
      out.write("					<h3>GIỚI THIỆU VỀ ORIFLAME</h3>\r\n");
      out.write("					<p>Chúng tôi là ai</p>\r\n");
      out.write("					<p>Tin tức hoạt động</p>\r\n");
      out.write("					<p>Chăm Sóc Khách Hàng</p>\r\n");
      out.write("					<p>Cơ hội nghề nghiệp</p>\r\n");
      out.write("					<p>Dành cho nhà đầu tư</p>\r\n");
      out.write("					<p>Oriflame toàn cầu</p>\r\n");
      out.write("				</div>\r\n");
      out.write("				<div class=\"col-sm-6 col-md-4 col-lg-3\">\r\n");
      out.write("					<h3>THÔNG TIN HOẠT ĐỘNG KINH DOANH</h3>\r\n");
      out.write("					<p>Các tài liệu về hoạt động bán hàng</p>\r\n");
      out.write("					<p>đa cấp của doanh nghiệp</p>\r\n");
      out.write("					<p>Thông tin về hoạt động kinh doanh</p>\r\n");
      out.write("					<p>bán hàng đa cấp của doanh nghiệp</p>\r\n");
      out.write("					<p>Các quy trình, thủ tục</p>\r\n");
      out.write("					<p>Chăm Sóc Khách Hàng</p>\r\n");
      out.write("				</div>\r\n");
      out.write("				<div class=\"col-sm-6 col-md-4 col-lg-3\">\r\n");
      out.write("					<h3>Xem thêm & Tải về</h3>\r\n");
      out.write("					<p>Các tài liệu về hoạt động bán hàng</p>\r\n");
      out.write("				</div>\r\n");
      out.write("			</div>\r\n");
      out.write("		</div>\r\n");
      out.write("	</nav>\r\n");
      out.write("</body>\r\n");
      out.write("</html>");
      out.write("\r\n");
      out.write("\r\n");
      out.write("	<script src=\"https://code.jquery.com/jquery-3.2.1.slim.min.js\" type=\"text/javascript\"></script>\r\n");
      out.write("	<script src=\"https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.12.9/umd/popper.min.js\" type=\"text/javascript\"></script>\r\n");
      out.write("	<script src=\"https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/js/bootstrap.min.js\" type=\"text/javascript\"></script>\r\n");
      out.write("\r\n");
      out.write("</body>\r\n");
      out.write("</html>");
    } catch (java.lang.Throwable t) {
      if (!(t instanceof javax.servlet.jsp.SkipPageException)){
        out = _jspx_out;
        if (out != null && out.getBufferSize() != 0)
          try {
            if (response.isCommitted()) {
              out.flush();
            } else {
              out.clearBuffer();
            }
          } catch (java.io.IOException e) {}
        if (_jspx_page_context != null) _jspx_page_context.handlePageException(t);
        else throw new ServletException(t);
      }
    } finally {
      _jspxFactory.releasePageContext(_jspx_page_context);
    }
  }

  private boolean _jspx_meth_c_005furl_005f0(javax.servlet.jsp.PageContext _jspx_page_context)
          throws java.lang.Throwable {
    javax.servlet.jsp.PageContext pageContext = _jspx_page_context;
    javax.servlet.jsp.JspWriter out = _jspx_page_context.getOut();
    //  c:url
    org.apache.taglibs.standard.tag.rt.core.UrlTag _jspx_th_c_005furl_005f0 = (org.apache.taglibs.standard.tag.rt.core.UrlTag) _005fjspx_005ftagPool_005fc_005furl_0026_005fvalue_005fnobody.get(org.apache.taglibs.standard.tag.rt.core.UrlTag.class);
    boolean _jspx_th_c_005furl_005f0_reused = false;
    try {
      _jspx_th_c_005furl_005f0.setPageContext(_jspx_page_context);
      _jspx_th_c_005furl_005f0.setParent(null);
      // /decorators/user.jsp(15,16) name = value type = null reqTime = true required = false fragment = false deferredValue = false expectedTypeName = null deferredMethod = false methodSignature = null
      _jspx_th_c_005furl_005f0.setValue("/templates/user/css/style.css");
      int _jspx_eval_c_005furl_005f0 = _jspx_th_c_005furl_005f0.doStartTag();
      if (_jspx_th_c_005furl_005f0.doEndTag() == javax.servlet.jsp.tagext.Tag.SKIP_PAGE) {
        return true;
      }
      _005fjspx_005ftagPool_005fc_005furl_0026_005fvalue_005fnobody.reuse(_jspx_th_c_005furl_005f0);
      _jspx_th_c_005furl_005f0_reused = true;
    } finally {
      org.apache.jasper.runtime.JspRuntimeLibrary.releaseTag(_jspx_th_c_005furl_005f0, _jsp_getInstanceManager(), _jspx_th_c_005furl_005f0_reused);
    }
    return false;
  }

  private boolean _jspx_meth_c_005furl_005f1(javax.servlet.jsp.PageContext _jspx_page_context)
          throws java.lang.Throwable {
    javax.servlet.jsp.PageContext pageContext = _jspx_page_context;
    javax.servlet.jsp.JspWriter out = _jspx_page_context.getOut();
    //  c:url
    org.apache.taglibs.standard.tag.rt.core.UrlTag _jspx_th_c_005furl_005f1 = (org.apache.taglibs.standard.tag.rt.core.UrlTag) _005fjspx_005ftagPool_005fc_005furl_0026_005fvalue_005fnobody.get(org.apache.taglibs.standard.tag.rt.core.UrlTag.class);
    boolean _jspx_th_c_005furl_005f1_reused = false;
    try {
      _jspx_th_c_005furl_005f1.setPageContext(_jspx_page_context);
      _jspx_th_c_005furl_005f1.setParent(null);
      // /common/user/header.jsp(29,13) name = value type = null reqTime = true required = false fragment = false deferredValue = false expectedTypeName = null deferredMethod = false methodSignature = null
      _jspx_th_c_005furl_005f1.setValue("/stylecss/base/basecss.css");
      int _jspx_eval_c_005furl_005f1 = _jspx_th_c_005furl_005f1.doStartTag();
      if (_jspx_th_c_005furl_005f1.doEndTag() == javax.servlet.jsp.tagext.Tag.SKIP_PAGE) {
        return true;
      }
      _005fjspx_005ftagPool_005fc_005furl_0026_005fvalue_005fnobody.reuse(_jspx_th_c_005furl_005f1);
      _jspx_th_c_005furl_005f1_reused = true;
    } finally {
      org.apache.jasper.runtime.JspRuntimeLibrary.releaseTag(_jspx_th_c_005furl_005f1, _jsp_getInstanceManager(), _jspx_th_c_005furl_005f1_reused);
    }
    return false;
  }

  private boolean _jspx_meth_c_005furl_005f2(javax.servlet.jsp.PageContext _jspx_page_context)
          throws java.lang.Throwable {
    javax.servlet.jsp.PageContext pageContext = _jspx_page_context;
    javax.servlet.jsp.JspWriter out = _jspx_page_context.getOut();
    //  c:url
    org.apache.taglibs.standard.tag.rt.core.UrlTag _jspx_th_c_005furl_005f2 = (org.apache.taglibs.standard.tag.rt.core.UrlTag) _005fjspx_005ftagPool_005fc_005furl_0026_005fvalue_005fnobody.get(org.apache.taglibs.standard.tag.rt.core.UrlTag.class);
    boolean _jspx_th_c_005furl_005f2_reused = false;
    try {
      _jspx_th_c_005furl_005f2.setPageContext(_jspx_page_context);
      _jspx_th_c_005furl_005f2.setParent(null);
      // /common/user/header.jsp(31,13) name = value type = null reqTime = true required = false fragment = false deferredValue = false expectedTypeName = null deferredMethod = false methodSignature = null
      _jspx_th_c_005furl_005f2.setValue("/css/bootstrap.css");
      int _jspx_eval_c_005furl_005f2 = _jspx_th_c_005furl_005f2.doStartTag();
      if (_jspx_th_c_005furl_005f2.doEndTag() == javax.servlet.jsp.tagext.Tag.SKIP_PAGE) {
        return true;
      }
      _005fjspx_005ftagPool_005fc_005furl_0026_005fvalue_005fnobody.reuse(_jspx_th_c_005furl_005f2);
      _jspx_th_c_005furl_005f2_reused = true;
    } finally {
      org.apache.jasper.runtime.JspRuntimeLibrary.releaseTag(_jspx_th_c_005furl_005f2, _jsp_getInstanceManager(), _jspx_th_c_005furl_005f2_reused);
    }
    return false;
  }

  private boolean _jspx_meth_decorator_005fbody_005f0(javax.servlet.jsp.PageContext _jspx_page_context)
          throws java.lang.Throwable {
    javax.servlet.jsp.PageContext pageContext = _jspx_page_context;
    javax.servlet.jsp.JspWriter out = _jspx_page_context.getOut();
    //  decorator:body
    com.opensymphony.module.sitemesh.taglib.decorator.BodyTag _jspx_th_decorator_005fbody_005f0 = (com.opensymphony.module.sitemesh.taglib.decorator.BodyTag) _005fjspx_005ftagPool_005fdecorator_005fbody_005fnobody.get(com.opensymphony.module.sitemesh.taglib.decorator.BodyTag.class);
    boolean _jspx_th_decorator_005fbody_005f0_reused = false;
    try {
      _jspx_th_decorator_005fbody_005f0.setPageContext(_jspx_page_context);
      _jspx_th_decorator_005fbody_005f0.setParent(null);
      int _jspx_eval_decorator_005fbody_005f0 = _jspx_th_decorator_005fbody_005f0.doStartTag();
      if (_jspx_th_decorator_005fbody_005f0.doEndTag() == javax.servlet.jsp.tagext.Tag.SKIP_PAGE) {
        return true;
      }
      _005fjspx_005ftagPool_005fdecorator_005fbody_005fnobody.reuse(_jspx_th_decorator_005fbody_005f0);
      _jspx_th_decorator_005fbody_005f0_reused = true;
    } finally {
      org.apache.jasper.runtime.JspRuntimeLibrary.releaseTag(_jspx_th_decorator_005fbody_005f0, _jsp_getInstanceManager(), _jspx_th_decorator_005fbody_005f0_reused);
    }
    return false;
  }

  private boolean _jspx_meth_c_005furl_005f3(javax.servlet.jsp.PageContext _jspx_page_context)
          throws java.lang.Throwable {
    javax.servlet.jsp.PageContext pageContext = _jspx_page_context;
    javax.servlet.jsp.JspWriter out = _jspx_page_context.getOut();
    //  c:url
    org.apache.taglibs.standard.tag.rt.core.UrlTag _jspx_th_c_005furl_005f3 = (org.apache.taglibs.standard.tag.rt.core.UrlTag) _005fjspx_005ftagPool_005fc_005furl_0026_005fvalue_005fnobody.get(org.apache.taglibs.standard.tag.rt.core.UrlTag.class);
    boolean _jspx_th_c_005furl_005f3_reused = false;
    try {
      _jspx_th_c_005furl_005f3.setPageContext(_jspx_page_context);
      _jspx_th_c_005furl_005f3.setParent(null);
      // /common/user/footer.jsp(31,12) name = value type = null reqTime = true required = false fragment = false deferredValue = false expectedTypeName = null deferredMethod = false methodSignature = null
      _jspx_th_c_005furl_005f3.setValue("/stylecss/base/basecss.css");
      int _jspx_eval_c_005furl_005f3 = _jspx_th_c_005furl_005f3.doStartTag();
      if (_jspx_th_c_005furl_005f3.doEndTag() == javax.servlet.jsp.tagext.Tag.SKIP_PAGE) {
        return true;
      }
      _005fjspx_005ftagPool_005fc_005furl_0026_005fvalue_005fnobody.reuse(_jspx_th_c_005furl_005f3);
      _jspx_th_c_005furl_005f3_reused = true;
    } finally {
      org.apache.jasper.runtime.JspRuntimeLibrary.releaseTag(_jspx_th_c_005furl_005f3, _jsp_getInstanceManager(), _jspx_th_c_005furl_005f3_reused);
    }
    return false;
  }

  private boolean _jspx_meth_c_005furl_005f4(javax.servlet.jsp.PageContext _jspx_page_context)
          throws java.lang.Throwable {
    javax.servlet.jsp.PageContext pageContext = _jspx_page_context;
    javax.servlet.jsp.JspWriter out = _jspx_page_context.getOut();
    //  c:url
    org.apache.taglibs.standard.tag.rt.core.UrlTag _jspx_th_c_005furl_005f4 = (org.apache.taglibs.standard.tag.rt.core.UrlTag) _005fjspx_005ftagPool_005fc_005furl_0026_005fvalue_005fnobody.get(org.apache.taglibs.standard.tag.rt.core.UrlTag.class);
    boolean _jspx_th_c_005furl_005f4_reused = false;
    try {
      _jspx_th_c_005furl_005f4.setPageContext(_jspx_page_context);
      _jspx_th_c_005furl_005f4.setParent(null);
      // /common/user/footer.jsp(33,12) name = value type = null reqTime = true required = false fragment = false deferredValue = false expectedTypeName = null deferredMethod = false methodSignature = null
      _jspx_th_c_005furl_005f4.setValue("/css/bootstrap.css");
      int _jspx_eval_c_005furl_005f4 = _jspx_th_c_005furl_005f4.doStartTag();
      if (_jspx_th_c_005furl_005f4.doEndTag() == javax.servlet.jsp.tagext.Tag.SKIP_PAGE) {
        return true;
      }
      _005fjspx_005ftagPool_005fc_005furl_0026_005fvalue_005fnobody.reuse(_jspx_th_c_005furl_005f4);
      _jspx_th_c_005furl_005f4_reused = true;
    } finally {
      org.apache.jasper.runtime.JspRuntimeLibrary.releaseTag(_jspx_th_c_005furl_005f4, _jsp_getInstanceManager(), _jspx_th_c_005furl_005f4_reused);
    }
    return false;
  }
}
