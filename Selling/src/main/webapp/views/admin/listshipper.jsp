<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@ include file="/common/taglist.jsp"%>

<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Danh sách shipper</title>


</head>
<body>
	<link
		href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css"
		rel="stylesheet"
		integrity="sha384-T3c6CoIi6uLrA9TneNEoa7RxnatzjcDSCmG1MXxSR1GAsXEV/Dwwykc2MPK8M2HN"
		crossorigin="anonymous">
	<link rel="stylesheet"
		href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.3/css/all.min.css">

	<link rel="stylesheet" type="text/css"
		href="${pageContext.request.contextPath}/templates/admin/css/stylelistshipper.css">

	<!--  content -->
	<link rel="stylesheet"
		href="https://cdnjs.cloudflare.com/ajax/libs/boxicons/2.1.0/css/boxicons.min.css"
		integrity="sha512-pVCM5+SN2+qwj36KonHToF2p1oIvoU3bsqxphdOIWMYmgr4ZqD3t5DjKvvetKhXGc/ZG5REYTT6ltKfExEei/Q=="
		crossorigin="anonymous" referrerpolicy="no-referrer" />
	<link rel="stylesheet"
		href="https://cdnjs.cloudflare.com/ajax/libs/MaterialDesign-Webfont/5.3.45/css/materialdesignicons.css"
		integrity="sha256-NAxhqDvtY0l4xn+YVa6WjAcmd94NNfttjNsDmNatFVc="
		crossorigin="anonymous" />

	<div class="list d-flex justify-content-center align-items-center">
		<a href="listuser" class="btn btn-outline-primary">Khách hàng</a>
		<a href="listseller" class="btn btn-outline-primary">Nhân viên</a>
		<a href="listshipper" class="btn btn-outline-primary">Shipper</a>
	</div>
	<div class="search">
		<div class="row justify-content-center">
			<div class="col-30 col-md-30 col-lg-15">
				<form class="card card-sm">
					<div class="card-body row no-gutters align-items-center">
						<div class="col-auto">
							<i class="fas fa-search h4 text-body"></i>
						</div>
						<!--end of col-->
						<div class="col-md">
							<input class="form-control" type="search" name="search_info"
								placeholder="Nhập shipper cần tìm">
						</div>
						<!--end of col-->
						<div class="col-auto">
							<button class="btn btn-success" type="submit">Tìm kiếm</button>
						</div>
						<!--end of col-->
					</div>
				</form>
			</div>
			<!--end of col-->
		</div>
	</div>


	<div class="container">
		<div class="row align-items-center">
			<div class="col-md-6">
				<div class="mb-3">
					<h5 class="card-title">
						Thông tin Shipper<span class="text-muted fw-normal ms-2">(${count })</span>
					</h5>
				</div>
			</div>
		</div>
		<div class="row">
			<div class="col-lg-12">
				<div class="">
					<div class="table-responsive">
						<table
							class="table project-list-table table-nowrap align-middle table-borderless">
							<thead>
								<tr>
									<th scope="col" class="ps-4" style="width: 50px;">
										<!-- <div class="form-check font-size-16"><input type="checkbox" class="form-check-input" id="contacusercheck" /><label class="form-check-label" for="contacusercheck"></label></div> -->
									</th>
									<th scope="col">Tài khoản</th>
									<th scope="col">Tổng đơn nhận</th>
									<th scope="col">Số điện thoại</th>
									<th scope="col" style="width: 200px;">Lựa chọn</th>
								</tr>
							</thead>
							<tbody>
								<c:forEach var="i" items="${list}">
									<tr>
										<th scope="row" class="ps-4">
											<div class="form-check font-size-16">
												<input type="checkbox" class="form-check-input"
													id="contacusercheck1" /><label class="form-check-label"
													for="contacusercheck1"></label>
											</div>
										</th>
										<td><img
											src="https://scontent.fsgn7-1.fna.fbcdn.net/v/t39.30808-6/357053034_814960390037893_4922475779121350488_n.jpg?_nc_cat=111&ccb=1-7&_nc_sid=efb6e6&_nc_eui2=AeF5HXwEGNMOPAGrytHpFsrR_aLOXQRBb7r9os5dBEFvuq1yibYhcbMKiV2CqFcBHaVpuYriGC2v8DMoF6Nbu4wB&_nc_ohc=Ze3ZaC8Fg1MAX9TG622&_nc_oc=AQmDWUE6_UmimeSiZ2jirGF78bMaWn8SsKj91n1Ww_KGUbXwiKAj3EL5_Xtj4yiHMKSNdJC5OZuK6Owbhrs6JfIF&_nc_ht=scontent.fsgn7-1.fna&oh=00_AfDd4v0R2q3tAdPWQOOKi9RUuY7XoWJkZjUWeP86-vEZ3A&oe=65746821"
											alt="" class="avatar-sm rounded-circle me-2" /> <a href="#"
											class="text-body">${i.employeeName}</a></td>
										<td><span class="badge badge-soft-success mb-0">20</span></td>
										<td>${i.phone }</td>
										<td>
											<ul class="list-inline mb-0">
												<li class="list-inline-item"><a
													href="javascript:void(0);" data-bs-toggle="tooltip"
													data-bs-placement="top" title="Edit"
													class="px-2 text-primary"><i
														class="bx bx-pencil font-size-18"></i></a></li>
												<li class="list-inline-item"><a
													href="javascript:void(0);" data-bs-toggle="tooltip"
													data-bs-placement="top" title="Delete"
													class="px-2 text-danger"><i
														class="bx bx-trash-alt font-size-18"></i></a></li>
											</ul>
										</td>
									</tr>
								</c:forEach>
							</tbody>
						</table>
					</div>
				</div>
			</div>
		</div>
		<div class="row g-0 align-items-center pb-4">
			<div class="col-sm-6">
				<div>
					<p class="mb-sm-0">Hiển thị 1 đến 10 trong 32 mục</p>
				</div>
			</div>
			<div class="col-sm-6">
				<div class="float-sm-end">
					<ul class="pagination mb-sm-0">
						<c:if test="${page<=1 }">
							<li class="page-item disabled"><a
								href="listshipper?page=${page - 1}" class="page-link"><i
									class="mdi mdi-chevron-left"></i></a></li>
						</c:if>
						<c:if test="${page>1 }">
							<li class="page-item"><a href="listshipper?page=${page - 1}"
								class="page-link"><i class="mdi mdi-chevron-left"></i></a></li>
						</c:if>
						<c:forEach var="i" begin="1" end="${num }">
							<c:if test="${i==page }">
								<li class="page-item active"><a
									href="listshipper?page=${i}" class="page-link">${i }</a></li>
							</c:if>
							<c:if test="${i!=page }">
								<li class="page-item"><a href="listshipper?page=${i}"
									class="page-link">${i }</a></li>
							</c:if>
						</c:forEach>
						<c:if test="${page<num}">
							<li class="page-item"><a href="listshipper?page=${page + 1}"
								class="page-link"><i class="mdi mdi-chevron-right"></i></a></li>
						</c:if>
						<c:if test="${page>=num}">
							<li class="page-item disabled"><a
								href="listshipper?page=${page + 1}" class="page-link"><i
									class="mdi mdi-chevron-right"></i></a></li>
						</c:if>

					</ul>
				</div>
			</div>
		</div>
	</div>
	<!-- end content-->


</body>
</html>