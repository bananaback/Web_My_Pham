package orishop.models;

import java.io.Serializable;
import java.sql.Date;
import java.sql.Time;
public class CustomerOrderedModels implements Serializable{
	private static final long serialVersionUID = 1L;
	
	private String orderID;
	private float orderTotal;
	private Date orderDate;
	private Time orderTime;
	private String deliveryID;
	private String cusID;
	public CustomerOrderedModels() {
		super();
	}
	public CustomerOrderedModels(String orderID, float orderTotal, Date orderDate, Time orderTime, String deliveryID,
			String cusID) {
		super();
		this.orderID = orderID;
		this.orderTotal = orderTotal;
		this.orderDate = orderDate;
		this.orderTime = orderTime;
		this.deliveryID = deliveryID;
		this.cusID = cusID;
	}
	public String getOrderID() {
		return orderID;
	}
	public void setOrderID(String orderID) {
		this.orderID = orderID;
	}
	public float getOrderTotal() {
		return orderTotal;
	}
	public void setOrderTotal(float orderTotal) {
		this.orderTotal = orderTotal;
	}
	public Date getOrderDate() {
		return orderDate;
	}
	public void setOrderDate(Date orderDate) {
		this.orderDate = orderDate;
	}
	public Time getOrderTime() {
		return orderTime;
	}
	public void setOrderTime(Time orderTime) {
		this.orderTime = orderTime;
	}
	public String getDeliveryID() {
		return deliveryID;
	}
	public void setDeliveryID(String deliveryID) {
		this.deliveryID = deliveryID;
	}
	public String getCusID() {
		return cusID;
	}
	public void setCusID(String cusID) {
		this.cusID = cusID;
	}
}