package orishop.DAO;

import java.util.List;

import orishop.models.CartItemModels;
import orishop.models.OrdersModels;

public interface IOrderDAO {
	List<OrdersModels> findAllOrders();
	void createOrder(OrdersModels model, int customerId, double totalPrice, List<CartItemModels> cartItems);
	
	List<OrdersModels> findOrderByShipperId(int id);
	
	List<OrdersModels> findOrderByShipperIdAndDistributed(int id);
}