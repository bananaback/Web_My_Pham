package orishop.DAO;

import java.util.List;

import orishop.models.*;

public interface IEmployeeDAO {
	List<EmployeeModels> findAll();
	List<EmployeeModels> findAllShipper();
	List<EmployeeModels> findAllSeller();
	
	EmployeeModels findShipper(int id);
	EmployeeModels findShipper(String name);
	List<EmployeeModels> findSellerBySellerName(String sellerName);
}
