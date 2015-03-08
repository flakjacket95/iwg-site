<?php
$this->load->view('templates/header');
?>
<h1>Applications/Programs</h1>
<p>As we run across useful programs and such, I will either mirror them here or post a link to their site and documentation. The point here is to attempt to collect as much information in one place as possible. Often we will spend 3/4 of a CTF Googleing versus actually attempting to solve challenges. Here are some tools we have found over time broken into categories. Some things here are skills rather than downloads.</p>
<h2>Section 1 - Tools and links</h2>
<div class="col-md-6"><h3>General Tools</h3>
<ol>
	<li>Command Line Tools&nbsp; &nbsp;<a href="http://www.nbcs.rutgers.edu/~edseries/UNIXcmds.html" target="_blank" class="btn btn-danger btn-xs">Link</a></li>
	<li>Wireshark - Packet Collection and Analysis&nbsp; &nbsp;<a href="https://www.wireshark.org/download.html" target="_blank" class="btn btn-danger btn-xs">Link</a></li>
</ol>
</div>
<div class="col-md-6 pull-right"><h3>Reverse Engineering</h3>
<ol class="col-md-6">
	<h4>Disassemblers and Decompilers</h4>
	<li>IDA Pro &nbsp; &nbsp;<a href="https://www.hex-rays.com/products/ida/support/download.shtml" target="_blank" class="btn btn-danger btn-xs">Link</a></li>
	<li>radare2&nbsp; &nbsp;<a href="http://www.hopperapp.com/" target="_blank" class="btn btn-danger btn-xs">Link</a></li>
	<li>objdump&nbsp; &nbsp;<a href="http://www.radare.org/y/?p=features" target="_blank" class="btn btn-danger btn-xs">Link</a></li>
	<li>Hopper&nbsp; &nbsp;<a href="http://linux.die.net/man/1/objdump" target="_blank" class="btn btn-danger btn-xs">Link</a></li>
</ol>
<p class="col-md-6"><h4>Documentation</h4>
Disassemblers allow a binary file to be interpreted without running. These are very useful for patching. They also can be used to analyze the program for issues such as Buffer Overflows or just to get a sense of what the program does.
<ul>
	<li><a href="https://www.hex-rays.com/products/ida/support/idadoc/index.shtml" target="_blank" class="btn btn-success btn-xs">IDA Manual</a></li>
	<li><a href="http://<?php echo base_url('files/resources/radare.pdf'); ?>" target="_blank" class="btn btn-success btn-xs">Radare Manual (pdf) - Mostly radare2 compatible</a></li>
	<li><a href="http://maijin.github.io/radare2book/" target="_blank" class="btn btn-success btn-xs">Radare2 Online Manual</a></li>
	<li><a href="http://unixhelp.ed.ac.uk/CGI/man-cgi?objdump+1" target="_blank" class="btn btn-success btn-xs">objdump man page</a></li>
	<li><a href="https://www.veracode.com/blog/2012/05/static-analysis-following-along-at-home-with-hoppers-decompiler-feature" target="_blank" class="btn btn-success btn-xs">Hopper</a></li>
</ul>

</p>
<div class="clearfix"></div>
<ol class="col-md-6">
	<h4>Debugger</h4>
	<li>gdb - Linux&nbsp; &nbsp;<a href="http://www.gnu.org/software/gdb/" target="_blank" class="btn btn-danger btn-xs">Link</a></li>
	<li>lldb - OSX Linux&nbsp; &nbsp;<a href="http://lldb.llvm.org/" target="_blank" class="btn btn-danger btn-xs">Link</a></li>
	<li>ollydbg - Windows&nbsp; &nbsp;<a href="http://www.ollydbg.de/" target="_blank" class="btn btn-danger btn-xs">Link</a></li>
	<li>windbg - Windows&nbsp; &nbsp;<a href="http://msdn.microsoft.com/en-us/windows/hardware/hh852365.aspx" target="_blank" class="btn btn-danger btn-xs">Link</a></li>
</ol>
<p class="col-md-6"><h4>Documentation</h4>
Debuggers allow you to dynamically reverse code. These tools also allow for the starting and stopping of a program at different points. The programs internal state can also be modified with a debugger.
<ul>
	<li><a href="https://sourceware.org/gdb/current/onlinedocs/gdb/" target="_blank" class="btn btn-success btn-xs">gdb Manual (Online)</a></li>
	<li><a href="http://<?php echo base_url('files/resources/gdbcheatsheet.pdf'); ?>" target="_blank" class="btn btn-success btn-xs">gdb Cheatsheet (pdf)</a></li>
	<li><a href="http://<?php echo base_url('files//gdbref.pdf'); ?>" target="_blank" class="btn btn-success btn-xs">gdb Cheatsheet 2(pdf)</a></li>
	<li><a href="https://sourceware.org/gdb/wiki/HomePage" target="_blank" class="btn btn-success btn-xs">gdb Wiki</a></li>
	<li><a href="http://lldb.llvm.org/tutorial.html" target="_blank" class="btn btn-success btn-xs">lldb Tutorial</a></li>
	<li><a href="http://thelegendofrandom.com/blog/sample-page" target="_blank" class="btn btn-success btn-xs">ollydbg Tutorials (Around 25)</a></li>
	<li><a href="http://blogs.msdn.com/b/cobold/archive/2009/09/03/windbg-tutorial-introduction.aspx" target="_blank" class="btn btn-success btn-xs">windbg Tutorial</a></li>
	<li><a href="https://msdn.microsoft.com/en-us/library/ff541398(v=vs.85).aspx" target="_blank" class="btn btn-success btn-xs">Microsoft Debugging Techniques</a></li>
</ul>

</p>
<ol class="col-md-6">
	<h4>Emulator</h4>
	<li>qemu&nbsp; &nbsp;<a href="http://wiki.qemu.org/Main_Page" target="_blank" class="btn btn-danger btn-xs">Link</a></li>
</ol>
<p>An emulator can be used to run a program intended for use on a different type of machine. Tools like this are invaluable as many CTF's will vary the binary constructions and types.</p>
<li><a href="http://wiki.qemu.org/Manual" target="_blank" class="btn btn-success btn-xs">Emulator Manual</a></li>
<ol class="col-md-6">
	<h4>SMT Solver</h4>
	<li>Z3&nbsp; &nbsp;<a href="http://z3.codeplex.com/" target="_blank" class="btn btn-danger btn-xs">Link</a></li>
</ol>
<p>An SMT solver can be used for many reverse engineering problems. These are very advanced though and take quite a bit of understanding. </p>
<li><a href="http://z3.codeplex.com/documentation" target="_blank" class="btn btn-success btn-xs">Z3 Documentation directory</a></li>
</div>







<h2>Section 2 - Usage Examples</h2>
<div class="col-md-6">

</div>
<?php
$this->load->view('templates/footer');
?>