package orishop.DAO;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;

import orishop.models.CartItemModels;
import orishop.models.OrdersModels;

public class OrderDAOImpl implements IOrderDAO{

	@Override
	public List<OrdersModels> findAllOrders() {
		List<OrdersModels> listOrder = new ArrayList<OrdersModels>();
		String sql = "SELECT * FROM ORDERS";
		try {
			new DBConnectionSQLServer();
			conn = DBConnectionSQLServer.getConnectionW();
			ps = conn.prepareStatement(sql);
			rs = ps.executeQuery();
			while (rs.next()) {
				OrdersModels orders = new OrdersModels();
				orders.setOrderId(rs.getInt("orderId"));
				orders.setOrderValue(rs.getFloat("orderValue"));
				orders.setOrderDate(rs.getDate("orderDate"));
				orders.setCartId(rs.getInt("cartId"));
				orders.setCustomerId(rs.getInt("customerId"));
				orders.setPaymentStatus(rs.getString("paymentStatus"));
				orders.setOrderStatus(rs.getString("orderStatus"));
				orders.setPaymentMethod(rs.getString("paymentMethod"));
				orders.setDeliveryMethod(rs.getString("deliveryMethod"));
				orders.setEmployeeId(rs.getInt("employeeId"));
				listOrder.add(orders);
			}
			conn.close();

		} catch (Exception e) {
			e.printStackTrace();
		}
		return listOrder;
	}

	@Override
	public void createOrder(OrdersModels model,int customerId, double totalPrice, List<CartItemModels> cartItems) {
				
		String sqlOrder = "INSERT INTO orders (orderValue, orderDate,cartId,customerId,paymentStatus,orderStatus,paymentMethod,deliveryMethod,employeeId) VALUES (?, getdate(), ?, ?, ?, ?, ?, ?, ?)";
		String sqlOrderDetail = "INSERT INTO order_item (productId, orderId, quantity, totalPrice) VALUES (?, ?, ?, ?)";
		try {

			new DBConnectionSQLServer();
			Connection conn = DBConnectionSQLServer.getConnectionW(); //ket noi CSDL
			PreparedStatement psOrder = conn.prepareStatement(sqlOrder); //ném câu lệnh sql
			PreparedStatement psOrderDetail = conn.prepareStatement(sqlOrderDetail);
			//Insert into order table		
			psOrder.setDouble(1, totalPrice);
			psOrder.setInt(2, model.getCart().getCartId());
            psOrder.setInt(3, customerId);
            psOrder.setString(4, "paying");
            psOrder.setString(5, "save");
            psOrder.setString(6, "qrcode");
            psOrder.setString(7, model.getDeliveryMethod());
            psOrder.setInt(8, model.getEmployeeId());
			psOrder.executeUpdate();
         // Insert into order_detail table
            for (CartItemModels cartItem : cartItems) {
                psOrderDetail.setInt(1, cartItem.getProductID());
                psOrderDetail.setInt(2, model.getOrderID());
                psOrderDetail.setInt(3, cartItem.getQuantity());
                psOrderDetail.setDouble(4, cartItem.getQuantity()*cartItem.getProduct().getPrice());
                psOrderDetail.executeUpdate();
            }
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	@Override
	public List<OrdersModels> findOrderByShipperId(int id) {
		String sql = "select * from orders where employeeId=?";
		List<OrdersModels> listorder = new ArrayList<OrdersModels>();
		try {
			new DBConnectionSQLServer();
			Connection conn = DBConnectionSQLServer.getConnectionW();
			PreparedStatement ps = conn.prepareStatement(sql);
			ps.setInt(1, id);
			ResultSet rs = ps.executeQuery();
			while(rs.next()) {
				OrdersModels model = new OrdersModels();
				model.setOrderID(rs.getInt("OrderID"));
				model.setOrderValue(rs.getFloat("OrderValue"));
				model.setOrderDate(rs.getDate("OrderDate"));
				model.setCartID(rs.getInt("CartID"));
				model.setCustomerID(rs.getInt("CustomerID"));
				model.setPaymentStatus(rs.getString("PaymentStatus"));
				model.setOrderStatus(rs.getString("OrderStatus"));
				model.setPaymentMethod(rs.getString("PaymentMethod"));
				model.setDeliveryMethod(rs.getString("DeliveryMethod"));
				model.setEmployeeId(rs.getInt("EmployeeID"));
				listorder.add(model);
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return listorder;
	}

	@Override
	public List<OrdersModels> findOrderByShipperIdAndDistributed(int id) {
		String sql = "select * from orders where employeeId=? and orderStatus = 'distributed'";
		List<OrdersModels> listorder = new ArrayList<OrdersModels>();
		try {
			new DBConnectionSQLServer();
			Connection conn = DBConnectionSQLServer.getConnectionW();
			PreparedStatement ps = conn.prepareStatement(sql);
			ps.setInt(1, id);
			ResultSet rs = ps.executeQuery();
			while(rs.next()) {
				OrdersModels model = new OrdersModels();
				model.setOrderID(rs.getInt("OrderID"));
				model.setOrderValue(rs.getFloat("OrderValue"));
				model.setOrderDate(rs.getDate("OrderDate"));
				model.setCartID(rs.getInt("CartID"));
				model.setCustomerID(rs.getInt("CustomerID"));
				model.setPaymentStatus(rs.getString("PaymentStatus"));
				model.setOrderStatus(rs.getString("OrderStatus"));
				model.setPaymentMethod(rs.getString("PaymentMethod"));
				model.setDeliveryMethod(rs.getString("DeliveryMethod"));
				model.setEmployeeId(rs.getInt("EmployeeID"));
				listorder.add(model);
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return listorder;
	}

}