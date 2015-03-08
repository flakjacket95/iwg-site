<?php
$this->load->view('templates/header');
?>
<h1>Change Password</h1>
<span style="color: red;">
<?php
if(isset($success))
{
	if($success == "Success!")
	{
		echo $success;
	}
	else
	{
		echo "ERROR: " . $success;
	}
}
?>
</span>
<form method="post" action="http://<?php echo site_url('welcome/passchange'); ?>" >
		<div class="form-group">
    		<div class="col-md-6 input-group">
     			<div class="input-group-addon">Old Password</div>
      			<input type="password" class="form-control" id="user" name="oldpassword">
    		</div>
 		</div>
		<div class="form-group">
    		<div class="col-md-6 input-group">
     			<div class="input-group-addon">New Password</div>
      			<input type="password" class="form-control" id="pass" name="newpassword">
    		</div>
 		</div>
 		<div class="form-group">
    		<div class="col-md-6 input-group">
     			<div class="input-group-addon">Confirm New Password</div>
      			<input type="password" class="form-control" id="pass" name="newpassword2">
    		</div>
 		</div>
 		<div class="form-group">
    		<div class="col-md-6 input-group">
      			<input type="submit" class="col-md-12 btn btn-success" id="submit" name="submit" value="Change Password">
    		</div>
 		</div>
 		</form>
<?php
$this->load->view('templates/footer');
?>