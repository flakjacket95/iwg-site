<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
	<meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
<title>IWG</title>
<link href="<?php echo site_url('../../../../../dist/css/bootstrap.min.css'); ?>" rel="stylesheet">
<link rel="stylesheet" type="text/css" href="<?php echo site_url('../../../../../css/dataTables.bootstrap.css'); ?>">
<link rel="stylesheet" href="<?php echo site_url('../../../../../css/style.css'); ?>">
<link rel="stylesheet" href="<?php echo site_url('../../../../../css/menu.css'); ?>">
<link rel="stylesheet" href="<?php echo site_url('../../../../../css/content.css'); ?>">
<link rel="shortcut icon" href="<?php echo site_url('../../../../../favicon.ico'); ?>" type="image/x-icon">
<link rel="icon" href="<?php echo site_url('../../../../../favicon.ico'); ?>" type="image/x-icon">
<style type="text/css">
</style>
<!--[if lt IE 9]>
      <script src="https://oss.maxcdn.com/html5shiv/3.7.2/html5shiv.min.js"></script>
      <script src="https://oss.maxcdn.com/respond/1.4.2/respond.min.js"></script>
<![endif]-->
<script src="<?php echo site_url('../../../../../js/jquery-2.1.1.min.js'); ?>"></script>
<script src="<?php echo site_url('../../../../../js/script.js'); ?>"></script>
<script>
$(document).ready(function() {  
var stickyNavTop = window.innerHeight;   
  
var stickyNav = function(){  
var scrollTop = $(window).scrollTop();  
       
if (scrollTop > stickyNavTop) {   
    $('.nav').addClass('sticky');  
} else {  
    $('.nav').removeClass('sticky');   
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
</head>
<body>
	<div class="wrapper">
		<!--<div class="top">
			<p id="write-text">
				>IWG:~$ <img id="cursor" src="<?php echo site_url('../../../../../images/blinking-cursor.gif'); ?>">
			</p>
		</div>-->
		<div class="nav" >
			<div class="left">
				IWG
			</div>
			<div class="menu">
				<ul>
					<li id="first" ><a class="hexchange" href="#" >Home</a></li>
					<li id="first" ><a class="hexchange" href="#" >Logout</a></li>
					<li id="first" class="active"><a class="hexchange" href="#">Training</a>
						<ul>
					         <li><a class="hexchange" href='#'>Beginners</a>
					            <ul>
					               <li><a class="hexchange" href='#'>Hacking</a>
									<ul>
					              		 <li><a class="hexchange" href='http://<?php echo site_url('welcome/begin_binary'); ?>'>Binary Attacks</a></li>
					              		 <li><a class="hexchange" href='#'>Web Attacks</a></li>
					              		 <li><a class="hexchange" href='#'>Forensic Attacks</a></li>
					              		 <li><a class="hexchange" href='#'>Exploitation</a></li>
					            	</ul>
					               </li>
					               <li><a class="hexchange" href='#'>Policy</a></li>
					            </ul>
					         </li>
					         <li><a class="hexchange" href='#'>Advanced</a>
					            <ul>
					              	<li><a class="hexchange" href='#'>Binary Attacks</a></li>
					              	<li><a class="hexchange" href='#'>Web Attacks</a></li>
					              	<li><a class="hexchange" href='#'>Forensic Attacks</a></li>
					              	<li><a class="hexchange" href='#'>Exploitation</a></li>
					            </ul>
					         </li>
					      </ul>
					</li>
					<li id="first" class="active"><a class="hexchange" href="#">Tools</a>
						<ul>
					         <li><a class="hexchange" href='#'>VM's</a>
					            <ul>
					               <li><a class="hexchange" href='#'>Downloads</a></li>
					               <li><a class="hexchange" href='#'>Academy</a></li>
					            </ul>
					         </li>
					         <li><a class="hexchange" href='#'>Systems</a>
					            <ul>
					               <li><a class="hexchange" href='#'>Servers</a></li>
					               <li><a class="hexchange" href='#'>Computational</a></li>
					            </ul>
					         </li>
					         <li><a class="hexchange" href='#'>Applications</a></li>
					      </ul>
					</li>
					<li id="first" class="active"><a  class="hexchange" href="#">Other</a>
						<ul>
					         <li><a class="hexchange" href='#'>Leadership</a></li>
					         <li><a class="hexchange" href='#'>Schedule</a></li>
					      </ul>
					</li>
					<li id="first" ><a class="hexchange" href="#">Forum</a></li>
				</ul>
			</div>
		</div>
		<div class="content">