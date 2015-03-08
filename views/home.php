<?php
$this->load->view('templates/header');
?>
<h1>IWG Internal Web page</h1>
<div class="col-md-12">
	<p>Well the good news is that we have a database setup and running, in case you couldn't figure that out by the new login functionality. If you want to change your site password, use the utility at the bottom (in the footer). In the meantime, the forum is up and running under phpBB3 and will be migrated to myBB here soon. CDX 2105 is approaching, lets make sure we destroy it this year. In other news, you probably know about the site issues here. They are still a work in progress.  

	</p>
<h2>On another note</h2>
<p>I still need a few volunteers to assist in the compiling of data onto this site. This does not necessarily require detailed knowledge of everything but, rather a decent method of note taking and the force (Google that is). There are a lot of things to cover and they get overwhelming. Send me an email if you wish to assist! Thanks!</p>
<h2>Planned Add ons</h2>
<p>Huh? They are all done! Look at that. If you have ideas, be sure to let me know when you see me. A few long-term projects I would like to start are listed: </p>
<ol>
	<li>Exhaustive Resource List - Broken down by application(web, binary, etc) and usage</li>
	<li>Writeup database - Search-able with stringent terms - cut down on our Google time.</li>
	<li>Challenges we have solved, and how we did it. Typically done with a write-up but, this will be an attempt to document the actual solution <i>process</i> as well as the concept behind it.
		<ul>
			<li>How the Python solution code was written</li>
			<li>What lead to the original decision to Google the specific keywords</li>
			<li>How was the information found used or how was the tool installed and used.</li>
			<li>Problems! Nobodies perfect! What happened, you got the wrong version and had to upgrade or accidental followed a Red Herring in the challenge</li>
			<li>As much info as possible</li>
		</ul>
	</li>
	<li>Group Exercises: We are a team so we need some practice solving challenges this as well. Some challenges require pure imagination. 20 minds will always thing about something different than one only. Thank Wilhelm for this idea.</li>
</ol>
<p>Most hacking groups learn via various different avenues. I believe that we would all benefit from the same general thinking as someone else. When we are faced with a problem, immediatly we attempt to solve it and if we are successful we omit details on how we figured out how to start in the first place. There are hundreds of write-ups out there that document very specific security flaws and their exploits. What is undocumented is the identification of those issues, especially from a binary perspective. Everyone has to learn about how to approach a problem, that is something I would like to begin to develop.</p>
</div>
<?php 
$this->load->view('directory');
?>
<?php
$this->load->view('templates/footer');
?>