<?php
$this->load->view('templates/header');
?>
<h1>Cyberstakes 2014</h1>
<h2>Educating the Educator Resources</h2>
<p>Items 8 and 9 are examples problems and solutions</p>
<ol>
	<li><a href="http://<?php echo base_url('files/pptx/bypassing_defenses.pptx'); ?>">Bypassing Defenses</a></li>
	<li><a href="http://<?php echo base_url('files/pptx/crypto.pptx'); ?>">Cryptgraphy</a></li>
	<li><a href="http://<?php echo base_url('files/pptx/exploitation.pptx'); ?>">Exploitation</a></li>
	<li><a href="http://<?php echo base_url('files/pptx/live.pptx'); ?>">Live Exercise Notes</a></li>
	<li><a href="http://<?php echo base_url('files/pptx/patching.pptx'); ?>">Patching</a></li>
	<li><a href="http://<?php echo base_url('files/pptx/reversing.pptx'); ?>">Reversing</a></li>
	<li><a href="http://<?php echo base_url('files/pptx/web.pptx'); ?>">Web</a></li>
	<li><a href="http://<?php echo base_url('files/cyberstakes/ete_problems.zip'); ?>">Problems</a></li>
	<li><a href="http://<?php echo base_url('files/cyberstakes/ete_handouts_with_source.zip'); ?>">Problems with Source</a></li>
</ol>
<p>Coming Soon...
	Cyberstakes has released a .ova file containing all of the problems from the 2014 event. The login information is user:ioctf pass:ioctf. The link below is to their page, I will mirror it when possible.</p>
<a href="https://cyberstakesonline.com/workshop/downloads/IOCTF%20Live%202014.ova">Cyberstakes 2014 OVA</a> Note: This file is 892 MB in size. 
<?php
$this->load->view('modals');
$this->load->view('templates/footer');
?>