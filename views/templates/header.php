<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
	<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
<title>IWG</title>
<link href="http://<?php echo base_url('dist/css/bootstrap.min.css'); ?>" rel="stylesheet">
<link rel="stylesheet" type="text/css" href="http://<?php echo base_url('css/dataTables.bootstrap.css'); ?>">
<link rel="stylesheet" href="http://<?php echo base_url('css/prism.css'); ?>">
<link rel="stylesheet" href="http://<?php echo base_url('css/style.css'); ?>">
<link rel="stylesheet" href="http://<?php echo base_url('css/menu.css'); ?>">
<link rel="stylesheet" href="http://<?php echo base_url('css/content.css'); ?>">
<link rel="stylesheet" href="http://<?php echo base_url('css/font-awesome-4.2.0/css/font-awesome.min.css'); ?>">
<link rel="shortcut icon" href="http://<?php echo base_url('favicon.ico'); ?>" type="image/x-icon">
<link rel="icon" href="http://<?php echo base_url('favicon.ico'); ?>" type="image/x-icon">
<style type="text/css">
</style>
<!--[if lt IE 9]>
      <script src="https://oss.maxcdn.com/html5shiv/3.7.2/html5shiv.min.js"></script>
      <script src="https://oss.maxcdn.com/respond/1.4.2/respond.min.js"></script>
<![endif]-->
<script src="http://<?php echo base_url('js/jquery-2.1.1.min.js'); ?>"></script>
<script src="http://<?php echo base_url('js/script.js'); ?>"></script>
<script>
$(document).ready(function() {  
var stickyNavTop = window.innerHeight;   
  
var stickyNav = function(){  
var scrollTop = $(window).scrollTop();  
       
if (scrollTop > stickyNavTop) {   
    $('.navi').addClass('sticky');
    $('.content').addClass('down');
} else {  
    $('.navi').removeClass('sticky');
    $('.content').removeClass('down');   
}  
};  
  
stickyNav();  
  
$(window).scroll(function() {  
    stickyNav();  
});  
});
$(document).ready(function() {
	$('.top').css('height', window.innerHeight);
});
$(window).resize(function() {
	$('.top').css('height', window.innerHeight);
});
</script>
<?php if(!isset($firstpage)):?>
<script>
$(document).ready(function() {
    $('html, body').animate({
        scrollTop: $("#first").offset().top
    }, 3000);
});
</script>
<?php endif; ?>
</head>
<body>
	<script>
	var name = "<?php echo $this->session->userdata('name'); ?>";
	</script>
	<div class="wrapper">
		<div id="top" class="top">
			<?php if (isset($firstpage)):?>
			<p id="write-text">
				>IWG:~$ <img id="cursor" alt="Blinker" src="http://<?php echo base_url('images/blinking-cursor.gif'); ?>">
			</p>
		<?php else: ?>
			<p>>IWG:~$ IWG (core dumped)<img id="cursors" src="http://<?php echo base_url('images/blinking-cursor.gif'); ?>"></p>
		<?php endif; ?>
		</div>
		<div class="navi" >
			<div class="left">
				IWG
			</div>
			<!-- <div class="pull-left greet">
			<?php 
				echo  "Welcome " . $this->session->userdata('rank') . " " . $this->session->userdata('name');
			?>
			</div>-->
			<div class="menu">
				<ul>
					<li id="first" ><a class="hexchange" href="http://<?php echo site_url('welcome/home'); ?>" >Home</a></li>
					<li id="first" ><a class="hexchange" href="http://<?php echo site_url('session/logout'); ?>" >Logout</a></li>
					<li id="first" class="active"><a class="hexchange" href="#">Training</a>
						<ul>
					         <li><a class="hexchange" href='#'>Beginners</a>
					            <ul>
					               <li><a class="hexchange" href='#'>Hacking</a>
									<ul>
					              		 <li><a class="hexchange" href='http://<?php echo site_url('welcome/begin_binary'); ?>'>Binary Attacks</a></li>
					              		 <li><a class="hexchange" href='http://<?php echo site_url('welcome/begin_web'); ?>'>Web Attacks</a></li>
					              		 <li><a class="hexchange" href='http://<?php echo site_url('welcome/begin_foren'); ?>'>Forensic Attacks</a></li>
					              		 <li><a class="hexchange" href='http://<?php echo site_url('welcome/begin_exp'); ?>'>Exploitation</a></li>
					            	</ul>
					               </li>
					               <li><a class="hexchange" href='http://<?php echo site_url('welcome/policy'); ?>'>Policy</a></li>
					            </ul>
					         </li>
					         <li><a class="hexchange" href='#'>Advanced</a>
					            <ul>
					              	<li><a class="hexchange" href='http://<?php echo site_url('welcome/adv_binary'); ?>'>Binary Attacks</a></li>
					              	<li><a class="hexchange" href='http://<?php echo site_url('welcome/adv_web'); ?>'>Web Attacks</a></li>
					              	<li><a class="hexchange" href='http://<?php echo site_url('welcome/adv_foren'); ?>'>Forensic Attacks</a></li>
					              	<li><a class="hexchange" href='http://<?php echo site_url('welcome/adv_exp'); ?>'>Exploitation</a></li>
					            </ul>
					         </li>
					         <li><a class="hexchange" href='http://<?php echo site_url('welcome/article'); ?>'>Articles</a>
					      </ul>
					</li>
					<li id="first" class="active"><a class="hexchange" href="#">Tools</a>
						<ul>
					         <li><a class="hexchange" href='#'>VM's</a>
					            <ul>
					               <li><a class="hexchange" href='http://<?php echo site_url('welcome/downloads'); ?>'>Downloads</a></li>
					               <li><a class="hexchange" href='http://<?php echo site_url('welcome/academy'); ?>'>Academy</a></li>
					            </ul>
					         </li>
					         <li><a class="hexchange" href='#'>Systems</a>
					            <ul>
					               <li><a class="hexchange" href='http://<?php echo site_url('welcome/servers'); ?>'>Servers</a></li>
					               <li><a class="hexchange" href='http://<?php echo site_url('welcome/comput'); ?>'>Computational</a></li>
					            </ul>
					         </li>
					         <li><a class="hexchange" href='http://<?php echo site_url('welcome/apps'); ?>'>Applications</a></li>
					         <li><a class="hexchange" href='http://<?php echo site_url('welcome/info'); ?>'>Information</a></li>
					      </ul>
					</li>
					<li id="first" class="active"><a  class="hexchange" href="#">Other</a>
						<ul>
					         <li><a class="hexchange" href='http://<?php echo site_url('welcome/leaders'); ?>'>Leadership</a></li>
					         <li><a class="hexchange" href='http://<?php echo site_url('welcome/schedule'); ?>'>Schedule</a></li>
					         <li><a class="hexchange" href='http://<?php echo site_url('welcome/cdx'); ?>'>CDX</a></li>
					         <li><a class="hexchange" href='http://<?php echo site_url('welcome/cyberstakes'); ?>'>Cyberstakes</a></li>
					      </ul>
					</li>
					<?php if($this->session->userdata('access') >= 4): ?>
						<li id="first" class="active"><a  class="hexchange" href="#">Admin</a>
							<ul>
								<li><a class="hexchange" href='http://<?php echo site_url('welcome/ins_article'); ?>'>Add an Article</a></li>
							</ul>
						</li>
					<?php endif; ?>
					<li id="first" ><a class="hexchange" href="www.iwg.academy.usna.edu/forum">Forum</a></li>
				</ul>
			</div>
		</div>
		<div class="content">
			<div class="container-fluid">
				<div id="temp"></div>