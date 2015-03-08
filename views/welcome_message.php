<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
<title>IWG</title>
<link rel="stylesheet" href="css/style.css">
<link rel="shortcut icon" href="favicon.ico" type="image/x-icon">
<link rel="icon" href="favicon.ico" type="image/x-icon">
<link href="http://<?php echo base_url('dist/css/bootstrap.min.css'); ?>" rel="stylesheet">
<style type="text/css">
</style>
</head>
<body>
<center>
	<div class="container">
	<div class="mainpage">
		<h1>USNA Information Warfare Group</h1>
	</div>
	<div class="mainpage container-fluid">
		<p style="color: white;">In case you were curious. The USNA Information Warfare Group (IWG) is an ECA dedicated to the study of computational knowledge and techniques used to compromise computer systems. IWG travels all over the United States participating in competitions as well as cyber competitions hosted online. In the near future, look for more information to be displayed right here as well as lots of cool IWG stuff on our Public page.</p>
		<h2>Already a Member of IWG?</h2>
		<p>Use the login information you have been supplied to access this web page. </p>
		<form method="post" action="http://<?php echo site_url('session/login'); ?>" >
		<div class="form-group">
    		<div class="col-md-6 input-group">
     			<div class="input-group-addon">Username</div>
      			<input type="text" class="form-control" id="user" name="user">
    		</div>
 		</div>
		<div class="form-group">
    		<div class="col-md-6 input-group">
     			<div class="input-group-addon">Password</div>
      			<input type="password" class="form-control" id="pass" name="pass">
    		</div>
 		</div>
 		<div class="form-group">
    		<div class="col-md-6 input-group">
      			<input type="submit" class="col-md-12 btn btn-success" id="submit" name="submit" value="Login">
    		</div>
 		</div>
 		</form>
	</span>
	</div>
	</div>
</div>
</body>
<script src="http://<?php echo base_url('dist/js/bootstrap.min.js'); ?>"></script>
</html>