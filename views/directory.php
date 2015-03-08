<h1>Site Directory</h1>
<p class="col-md-12">Need to find something? This directory attempts to provide a method of quick navigation.</p>
<h2 class="col-md-6">What are you currently working on?</h2>
<div class="clearfix"></div>
<!-- Begin Selections-->
<div class="col-md-3 btn btn-primary" id="showa" onclick="display('a')">A CTF Competition</div>
<div class="col-md-3 btn btn-primary" onclick="display('b')">A Practice Problem</div>
<div class="col-md-3 btn btn-primary" onclick="display('c')">Just Reading and Learning</div>
<div class="col-md-3 btn btn-primary" onclick="display('d')">Trying to Find Some Information</div>
<div class="clearfix"></div>
<!-- CTF Related-->
<!--***********************************************************************************************************************************-->
<div style="display: none;" id="a">
	<h3>Okay. CTF it is. Which topic is closely related to the challenge?</h3>
	<li class="col-md-2 btn btn-success" onclick="display('e')">Web Attacks</li>
	<li class="col-md-2 btn btn-success" onclick="display('f')">Forensics</li>
	<li class="col-md-2 btn btn-success" onclick="display('g')">Overflows/Format Strings/Binary</li>
	<li class="col-md-2 btn btn-success" onclick="display('h')">Reversing</li>
	<li class="col-md-2 btn btn-success" onclick="display('i')">Other</li>
</div>
<div class="clearfix"></div>
<!-- Sub-contents Web-->
<div style="display: none;" class="well" id="e">
		<h3>Web Attacking</h3>
		<?php foreach($articles['web'] as $row): ?>
			<a class="btn btn-danger" href="http://<?php echo site_url("welcome/article/" . $row['t_id']); ?>" ><?php echo $row['title']; ?></a>
		<?php endforeach; ?>

		<h3>Databases</h3>
		<?php foreach($articles['db'] as $row): ?>
		<a class="btn btn-danger" href="http://<?php echo site_url("welcome/article/" . $row['t_id']); ?>" ><?php echo $row['title']; ?></a>
	<?php endforeach; ?>
</div>



<!-- Sub-contents Binary-->
<div style="display: none;" class="well" id="f">
	<h3>Forensics</h3>
	<?php foreach($articles['foren'] as $row): ?>
		<a class="btn btn-danger" href="http://<?php echo site_url("welcome/article/" . $row['t_id']); ?>" ><?php echo $row['title']; ?></a>
	<?php endforeach; ?>

</div>


<!-- Sub-contents -->
<div style="display: none;" class="well" id="g">
	<h3>Binary</h3>
	<?php foreach($articles['binary'] as $row): ?>
		<a class="btn btn-danger" href="http://<?php echo site_url("welcome/article/" . $row['t_id']); ?>" ><?php echo $row['title']; ?></a>
	<?php endforeach; ?>

</div>


<!-- Sub-contents -->
<div style="display: none;" class="well" id="h">
	<h3>Reversing</h3>
	<p></p>

</div>


<!-- Sub-contents -->
<div style="display: none;" class="well" id="i">
	<h3>Other</h3>
	<p></p>

</div>

<div style="display: none;" id="b">B contents</div>
<div style="display: none;" id="c">C contents</div>