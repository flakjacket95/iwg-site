<?php
$this->load->view('templates/header');
?>
<h1><?php if($level == "advanced"): ?>Advanced <?php else: ?> Basic <?php endif; ?> Binary</h1>
<?php if($level == "advanced"): ?>
<p>Advanced content has not been compiled yet. Want to work on this page? Send me an email at <a class="btn btn-xs btn-success" href="mailto: m171818@usna.edu">m171818 @ usna . edu</a></p>
<?php else: ?>
<ul class="nav nav-pills">
  <li role="presentation" class="active"><a href="#cybstk">Cyberstakes Challenges</a></li>
  <li role="presentation" class="active"><a href="#cybstksoln">Solutions</a></li>
  <li role="presentation" class="active"><a href="http://<?php echo base_url('files/pptx/reversing.pptx'); ?>">Cyberstakes&copy; Educate the Educator Reversing pptx</a></li>
</ul>
<h2 id="cybstk">Cyberstakes 2014 Challenges</h2>
<button type="button" class="btn btn-primary btn-lg" data-toggle="modal" data-target="#myModal">
  OBJDUMPME
</button>
<button type="button" class="btn btn-primary btn-lg" data-toggle="modal" data-target="#myModal2">
  READASM
</button>
<button type="button" class="btn btn-primary btn-lg" data-toggle="modal" data-target="#myModal3">
  CRASHME1
</button>
<h2 id="cybstksoln">Cyberstakes 2014 Solutions</h2>
<p>Solutions have not yet been posted. Try and solve the puzzles above that you have not yet solved. Solutions will be posted soon, check back and verify your answers when these are posted. </p>
<h2 id="">Using objdump to disassemble a binary</h2>
<p>Sometimes we will be provided with source code for a given problem. his is extremely helpful but, it is not guaranteed to be provided. There will be challenges where reading the asm is necessary. Also, finding a memory address is extremely important and easily done with objdump or gdb. Learning the ropes on these tools is imperative and further, learning to interpret and reverse the source from the assembly is an extremely helpful tool for the future.</p>
<p>Many more options for these commands and for different types of binaries are located on the Forensics page. The basic command we will use is located below:</p>
<kbd>objdump -d -Mintel binary | less</kbd>
<p>The flag -d tells objdump to disassemble the file. -Mintel tells the disassembler that we want the output to be in the Intel syntax, easier to read. binary represents the name of the file. Finally, we pipe the result into less so we can navigate and read it easily without scrolling all over the place. If you like working with files better, you can replace the <kbd>| less</kbd> with <kbd>> file.asm</kbd> which will redirect the output to a file.</p>

<h2 id="">Reading objdump output</h2>
	<h4></h4>
	<h4></h4>
	<h4></h4>
	<h4></h4>
<h2 id="">Endianness</h2>
<p class="col-md-7">Endianness refers to the computers method of storing <b>words</b> of data bay bytes in memory. In other words, memory stores data byte by byte. Sometimes data is not necessarily only a byte in length, case and point a memory address 0x0A0B0C0D is actually 4 bytes in size. When working through a compiler this concept is irrelevant. However, when overflowing a buffer, the data must be written in correctly otherwise it will be interpreted incorrectly. Recall that the stack has 4-byte segments and when calling a function the top one is the return address. Overflowing the buffer writes over the return address, calling a new function or causing a Segmentation Fault.</p>
<pre class="col-md-5">
+---------------------------+
|       Return Address      |   <-pushed before control is sent to the new function
+---------------------------+
|  Things from the function |
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
           So on
</pre>
<p class="col-md-8">Each of the blocks above is actually four bytes in size. It might look like this for real:</p>
<pre class="col-md-4">
+---------------------------+
|      |      |      |      |   <-Return Address
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
           So on
        is actually
+--------+
|        | <---One byte
|--------|
|        |
|--------|
|        |
|--------|
|        |
|--------|
~~~~~~~~~~
</pre>
<p>Two different methods of breaking 4 byte data up into these smaller pieces are big-endian and little-endian. Big means the most significant byte goes first and little is the opposite.</p>
<pre>
+--------+
|0A0B0C0D| <-Register
+--------+
Translates to
    +--+
  a:|0A|
    +--+
a+1:|0B|
    +--+   <- Big Endian
a+2:|0C|
    +--+
a+3:|0D|
    +--+

Or
    +--+
  a:|0D|
    +--+
a+1:|0C|
    +--+   <- Little Endian
a+2:|0B|
    +--+
a+3:|0A|
    +--+
</pre>
<p>Therefore, if you are overflowing a buffer in a little endian machine you need to write in the address 0x0A0B0C0D as \x0D\x0C\x0B\x0A otherwise you are actually calling the incorrect address (0x0D0C0B0A).
<?php endif; ?>
<?php
$this->load->view('modals');
$this->load->view('templates/footer');
?>