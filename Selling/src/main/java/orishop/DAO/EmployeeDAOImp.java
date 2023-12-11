package orishop.DAO;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;

import orishop.models.*;

public class EmployeeDAOImp implements IEmployeeDAO{
	
	Connection conn = null;
	PreparedStatement ps = null;
	ResultSet rs = null;
	
	public List<EmployeeModels> findAll() {
		List<EmployeeModels> listEmp = new ArrayList<EmployeeModels>();
		String sql = "SELECT * FROM Employee";
		try {
			conn = DBConnectionSQLServer.getConnectionW();
			ps = conn.prepareStatement(sql);
			rs = ps.executeQuery();
			while (rs.next()) {
                EmployeeModels employee = new EmployeeModels();
                employee.setEmployeeId(rs.getInt("employeeId"));
                employee.setEmployeeName(rs.getString("employeeName"));
                employee.setBirthdate(rs.getDate("birthdate"));
                employee.setGender(rs.getString("gender"));
                employee.setAddress(rs.getString("address"));
                employee.setPhone(rs.getString("phone"));
                employee.setMail(rs.getString("mail"));
                employee.setJob(rs.getString("job"));
                employee.setAccountId(rs.getInt("accountId"));
                employee.setActivityArea(rs.getString("activityArea"));
                employee.setImageURL(rs.getString("imageURL"));

                // Thêm đối tượng Employee vào danh sách
                listEmp.add(employee);
			}
		}catch (Exception e){
			e.printStackTrace();
		}
		return listEmp;
	}

	@Override
	public List<EmployeeModels> findAllShipper() {
		List<EmployeeModels> listEmp = new ArrayList<EmployeeModels>();
		String sql = "SELECT * FROM Employee where job='Shipper'";
		try {
			conn = DBConnectionSQLServer.getConnectionW();
			ps = conn.prepareStatement(sql);
			rs = ps.executeQuery();
			while (rs.next()) {
                EmployeeModels employee = new EmployeeModels();
                employee.setEmployeeId(rs.getInt("employeeId"));
                employee.setEmployeeName(rs.getString("employeeName"));
                employee.setBirthdate(rs.getDate("birthdate"));
                employee.setGender(rs.getString("gender"));
                employee.setAddress(rs.getString("address"));
                employee.setPhone(rs.getString("phone"));
                employee.setMail(rs.getString("mail"));
                employee.setJob(rs.getString("job"));
                employee.setAccountId(rs.getInt("accountId"));
                employee.setActivityArea(rs.getString("activityArea"));
                employee.setImageURL(rs.getString("imageURL"));

                // Thêm đối tượng Employee vào danh sách
                listEmp.add(employee);
			}
		}catch (Exception e){
			e.printStackTrace();
		}
		return listEmp;
	}

	@Override
	public List<EmployeeModels> findAllSeller() {
		List<EmployeeModels> listEmp = new ArrayList<EmployeeModels>();
		String sql = "SELECT * FROM Employee where job='Seller'";
		try {
			conn = DBConnectionSQLServer.getConnectionW();
			ps = conn.prepareStatement(sql);
			rs = ps.executeQuery();
			while (rs.next()) {
                EmployeeModels employee = new EmployeeModels();
                employee.setEmployeeId(rs.getInt("employeeId"));
                employee.setEmployeeName(rs.getString("employeeName"));
                employee.setBirthdate(rs.getDate("birthdate"));
                employee.setGender(rs.getString("gender"));
                employee.setAddress(rs.getString("address"));
                employee.setPhone(rs.getString("phone"));
                employee.setMail(rs.getString("mail"));
                employee.setJob(rs.getString("job"));
                employee.setAccountId(rs.getInt("accountId"));
                employee.setActivityArea(rs.getString("activityArea"));
                employee.setImageURL(rs.getString("imageURL"));

                // Thêm đối tượng Employee vào danh sách
                listEmp.add(employee);
			}
		}catch (Exception e){
			e.printStackTrace();
		}
		return listEmp;
	}

	@Override
	public EmployeeModels findShipper(int id) {
		String sql = "SELECT * FROM Employee where job='Shipper' and employeeId=?";
        EmployeeModels employee = new EmployeeModels();
		try {
			conn = DBConnectionSQLServer.getConnectionW();
			ps = conn.prepareStatement(sql);
			ps.setInt(1, id);
			rs = ps.executeQuery();
			if(rs.next()) {
				employee.setEmployeeId(rs.getInt("employeeId"));
	            employee.setEmployeeName(rs.getString("employeeName"));
	            employee.setBirthdate(rs.getDate("birthdate"));
	            employee.setGender(rs.getString("gender"));
	            employee.setAddress(rs.getString("address"));
	            employee.setPhone(rs.getString("phone"));
	            employee.setMail(rs.getString("mail"));
	            employee.setJob(rs.getString("job"));
	            employee.setAccountId(rs.getInt("accountId"));
	            employee.setActivityArea(rs.getString("activityArea"));
	            employee.setImageURL(rs.getString("imageURL"));
			} else {
				return null;
			}
		}catch (Exception e){
			e.printStackTrace();
		}
		return employee;
	}

	@Override
	public EmployeeModels findShipper(String name) {
		String sql = "SELECT * FROM Employee where job='Shipper' and employeeName=?";
        EmployeeModels employee = new EmployeeModels();  
		try {
			conn = DBConnectionSQLServer.getConnectionW();
			ps = conn.prepareStatement(sql);
			ps.setString(1, name);
			rs = ps.executeQuery();
			if(rs.next()) {
				employee.setEmployeeId(rs.getInt("employeeId"));
	            employee.setEmployeeName(rs.getString("employeeName"));
	            employee.setBirthdate(rs.getDate("birthdate"));
	            employee.setGender(rs.getString("gender"));
	            employee.setAddress(rs.getString("address"));
	            employee.setPhone(rs.getString("phone"));
	            employee.setMail(rs.getString("mail"));
	            employee.setJob(rs.getString("job"));
	            employee.setAccountId(rs.getInt("accountId"));
	            employee.setActivityArea(rs.getString("activityArea"));
	            employee.setImageURL(rs.getString("imageURL"));
			} else {
				return null;
			}
            
		}catch (Exception e){
			e.printStackTrace();
		}
		return employee;
	}
	
	public EmployeeModels findShipperByAccountID(int id) {
		String sql = "SELECT * FROM Employee where job='Shipper' and accountId=?";
        EmployeeModels employee = new EmployeeModels();
		try {
			conn = DBConnectionSQLServer.getConnectionW();
			ps = conn.prepareStatement(sql);
			ps.setInt(1, id);
			rs = ps.executeQuery();
			if(rs.next()) {
				employee.setEmployeeId(rs.getInt("employeeId"));
	            employee.setEmployeeName(rs.getString("employeeName"));
	            employee.setBirthdate(rs.getDate("birthdate"));
	            employee.setGender(rs.getString("gender"));
	            employee.setAddress(rs.getString("address"));
	            employee.setPhone(rs.getString("phone"));
	            employee.setMail(rs.getString("mail"));
	            employee.setJob(rs.getString("job"));
	            employee.setAccountId(rs.getInt("accountId"));
	            employee.setActivityArea(rs.getString("activityArea"));
	            employee.setImageURL(rs.getString("imageURL"));
			} else {
				return null;
			}
		}catch (Exception e){
			e.printStackTrace();
		}
		return employee;
	}
	
	public static void main(String[] args) {
		try {
			IEmployeeDAO emp = new EmployeeDAOImp();
			/*
			 * List<EmployeeModels> listEmp = emp.findAllSeller(); for(EmployeeModels e :
			 * listEmp) { System.out.println(e.getPhone()); }
			 */
			
			EmployeeModels empl = emp.findShipper("Employee17");
			System.out.println(empl.getPhone());
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	@Override
	public EmployeeModels findSeller(int id) {
		String sql = "SELECT * FROM Employee where job='Seller' and employeeId=?";
        EmployeeModels employee = new EmployeeModels();
		try {
			conn = DBConnectionSQLServer.getConnectionW();
			ps = conn.prepareStatement(sql);
			ps.setInt(1, id);
			rs = ps.executeQuery();
			if(rs.next()) {
	            employee.setEmployeeId(rs.getInt("employeeId"));
	            employee.setEmployeeName(rs.getString("employeeName"));
	            employee.setBirthdate(rs.getDate("birthdate"));
	            employee.setGender(rs.getString("gender"));
	            employee.setAddress(rs.getString("address"));
	            employee.setPhone(rs.getString("phone"));
	            employee.setMail(rs.getString("mail"));
	            employee.setJob(rs.getString("job"));
	            employee.setAccountId(rs.getInt("accountId"));
	            employee.setActivityArea(rs.getString("activityArea"));
	            employee.setImageURL(rs.getString("imageURL"));
            } else {
            	return null;
            }
		}catch (Exception e){
			e.printStackTrace();
		}
		return employee;
	}
	@Override
	public void updateEmployee(EmployeeModels employee) {
		String query = "update Employee set employeeName = ?, birthdate = ?, gender = ?, "
				+ "address = ?, phone = ?, mail = ? where employeeId = ?";
		
		try {
			conn = DBConnectionSQLServer.getConnectionW();
			ps = conn.prepareStatement(query);
			ps.setString(1, employee.getEmployeeName());
			ps.setDate(2, employee.getBirthdate());
			ps.setString(3, employee.getGender());
			ps.setString(4, employee.getAddress());
			ps.setString(5, employee.getPhone());
			ps.setString(6, employee.getMail());
			ps.setInt(7, employee.getEmployeeId());
			ps.executeUpdate();
			conn.close();
			
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
