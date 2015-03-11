<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
<title>IWG</title>
<link rel="stylesheet" href="css/style.css">
<link rel="shortcut icon" href="favicon.ico" type="image/x-icon">
<link rel="icon" href="favicon.ico" type="image/x-icon">
<script src="http://<?php echo base_url('js/jquery-2.1.1.min.js'); ?>"></script>
<link href="http://<?php echo base_url('dist/css/bootstrap.min.css'); ?>" rel="stylesheet">
<link rel="stylesheet" href="http://<?php echo base_url('css/prism.css'); ?>">
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
	<pre style="border: none; background: #333333;" class="col-md-5 language-c line-numbers"><code>int main(int argc, char* argv[]) {
	char var[] = "What is left?";
	if(password=="known" && username == "known") {
		printf("What are you waiting for? Login!");
	}
	else if (username="known" && password=="lost") {
		printf("Use password reset!");
	}
	else if(notiwgmember == true) {
		printf("Join now!");
	}
	else {
		printf(argv[1]);
	}
	return 0;
}</code></pre>
		<h2>Already a Member of IWG?</h2>
		<p>Uh-oh!. It looks like I made a, rather large, mistake in the instructions function, if you figure it out brownie points to you! If you figure it out and are not a member of IWG, you need to join! <a href="http://www.iwg.academy.usna.edu/mybb">Forum is here</a>
		</p>
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
 		<a data-toggle="modal" data-target="#modal">Lost Password?</a>
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

<div class="modal fade" id="modal" tabindex="-1" role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
        <button type="button" class="close" data-dismiss="modal"><span aria-hidden="true">&times;</span><span class="sr-only">Close</span></button>
        <h4 class="modal-title" id="myModalLabel">Oops!</h4>
      </div>
      <div class="modal-body">
        That's a shame! Either pull some complex cyber shenanigans or come find me to reset.
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
      </div>
    </div>
  </div>
</div>
</body>
<script src="http://<?php echo base_url('dist/js/bootstrap.min.js'); ?>"></script>
<script src="http://<?php echo base_url('js/prism.js'); ?>"></script>
</html>