<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Unauthorized Access</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 0;
            background-color: #f4f4f4;
        }
        .container {
            margin: 100px auto;
            width: 50%;
            text-align: center;
        }
        h1 {
            color: #ff6347;
        }
        p {
            color: #333;
        }
        a {
            color: #007bff;
            text-decoration: none;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Unauthorized Access</h1>
        <p>You are not authorized to access this page.</p>
        <p>Please <a href="${pageContext.request.contextPath}/web/login">login</a> to continue.</p>
    </div>
</body>
</html>
