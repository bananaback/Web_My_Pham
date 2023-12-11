package orishop.controllers.admin;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import orishop.DAO.CustomerDAOImp;
import orishop.DAO.IEmployeeDAO;
import orishop.models.CategoryModels;
import orishop.models.CustomerModels;
import orishop.models.EmployeeModels;
import orishop.services.CategoryServiceImp;
import orishop.services.CustomerServiceImp;
import orishop.services.EmployeeServiceImp;
import orishop.services.ICategoryService;
import orishop.services.ICustomerService;
import orishop.services.IEmployeeService;

@WebServlet(urlPatterns = {"/admin/listuser" , "/admin/userdetail","/admin/searchUser","/admin/searchShipper","/admin/searchSeller"})

public class AdminUserControllers extends HttpServlet {
	ICategoryService cateService = new CategoryServiceImp();
	IEmployeeService empService = new EmployeeServiceImp();
	ICustomerService cusService = new CustomerServiceImp();
	private static final long serialVersionUID = 1L;
	
	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		String url = req.getRequestURI();
		if(url.contains("admin/listuser")) {
			findAllUser(req, resp);
		} else if(url.contains("admin/userdetail")) {
			getUserDetail(req, resp);
		}
		else if(url.contains("admin/searchUser")) {
			getSearchUser(req, resp);
		}
		else if(url.contains("admin/searchSeller")) {
			getSearchSeller(req, resp);
		}
		else if(url.contains("admin/searchShipper")) {
			getSearchShipper(req, resp);
		}
	}
	private void getSearchUser(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		String usename = req.getParameter("search_info");
		List<CustomerModels> listcustomer = cusService.findCustomerByCustomerName(usename);
		
		req.setAttribute("list", listcustomer);
		RequestDispatcher rd = req.getRequestDispatcher("/views/admin/control_user/listuser.jsp");
		rd.forward(req, resp);
		
		
	}
	private void getSearchSeller(HttpServletRequest req, HttpServletResponse resp) {
		// TODO Auto-generated method stub
		
	}
	private void getSearchShipper(HttpServletRequest req, HttpServletResponse resp) {
		// TODO Auto-generated method stub
		
	}
	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException{
		String url = req.getRequestURI();
		if(url.contains("admin/searchUser")) {
			getSearchUser(req, resp);
		}
	}
	//region User
	private void findAllUser(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException{
		List<CustomerModels> listUser = cusService.findAll();
		
		int pagesize = 3;
		int size = listUser.size();
		int num = (size%pagesize==0 ? (size/pagesize) : (size/pagesize + 1));
		int page, numberpage = pagesize;
		String xpage = req.getParameter("page");
		if (xpage == null) {
			page = 1;
		}
		else {
			page = Integer.parseInt(xpage);
		}
		int start,end;
		start = (page - 1) * numberpage;
		end = Math.min(page*numberpage, size);
		
		List<CustomerModels> list = cusService.getListCustomerByPage(listUser, start, end);
		req.setAttribute("list", list);
		req.setAttribute("page", page);
		req.setAttribute("num", num);
		req.setAttribute("count", listUser.size());
		RequestDispatcher rd = req.getRequestDispatcher("/views/admin/listuser.jsp");
		rd.forward(req, resp);
	}
	
	private void getUserDetail(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException{
		req.setCharacterEncoding("UTF-8");
		resp.setCharacterEncoding("UTF-8");
		
		int id = Integer.valueOf(req.getParameter("id"));
		
		CustomerModels customer = cusService.findOne(id);
		
		req.setAttribute("customer", customer);
		
		RequestDispatcher rd = req.getRequestDispatcher("/views/admin/control_user/detailinforuser.jsp");
		rd.forward(req, resp);
	}
	
	//endregion

}
