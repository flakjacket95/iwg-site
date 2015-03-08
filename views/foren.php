<?php
$this->load->view('templates/header');
?>
<h1><?php if($level == "advanced"): ?>Advanced <?php else: ?> Basic <?php endif; ?> Forensics</h1>
<?php if($level == 'advanced'): ?>
<p>Advanced content has not been compiled yet. Want to work on this page? Send me an email at <a class="btn btn-xs btn-success" href="mailto: m171818@usna.edu">m171818 @ usna . edu</a></p>
<?php else: ?>
<ul class="nav nav-pills">
  <li role="presentation" class="active"><a href="#use">Useful Commands</a></li>
  <li role="presentation" class="active"><a href="#pipes">Pipes &amp; Redirtects</a></li>
  <li role="presentation" class="active"><a href="#other">Misc. Useful Commands</a></li>
  <li role="presentation" class="active"><a href="http://<?php echo base_url('files/pptx/crypto.pptx'); ?>">Cyberstakes&copy; Educate the Educator Forensics pptx</a></li>
</ul>
<h2 id="use">Useful Commands</h2>
<ul class="nav nav-pills">
  <li role="presentation" class="active"><a href="#grep">grep</a></li>
  <li role="presentation" class="active"><a href="#strings">strings</a></li>
  <li role="presentation" class="active"><a href="#tr">tr</a></li>
  <li role="presentation" class="active"><a href="#base64">base64</a></li>
  <li role="presentation" class="active"><a href="#sort">sort</a></li>
  <li role="presentation" class="active"><a href="#uniq">uniq</a></li>
  <li role="presentation" class="active"><a href="#find">find</a></li>
  <li role="presentation" class="active"><a href="#file">file</a></li>
  <li role="presentation" class="active"><a href="#xxd">xxd</a></li>
  <li role="presentation" class="active"><a href="#comp">Compression</a></li>
</ul>
<h2>Command Example GIFS</h2>
<p>The files used in these examples are supplied by Overthewire labs</p>
<ul class="nav nav-pills">
  <li role="presentation" class="active"><a target="_blank" href="http://<?php echo base_url('images/examples/grep.gif'); ?>">grep</a></li>
  <li role="presentation" class="active"><a target="_blank" href="http://<?php echo base_url('images/examples/strings.gif'); ?>">strings</a></li>
  <li role="presentation" class="active"><a target="_blank" href="http://<?php echo base_url('images/examples/tr.gif'); ?>">tr</a></li>
  <li role="presentation" class="active"><a target="_blank" href="http://<?php echo base_url('images/examples/base64.gif'); ?>">base64</a></li>
  <li role="presentation" class="active"><a target="_blank" href="http://<?php echo base_url('images/examples/sort.gif'); ?>">sort</a></li>
  <li role="presentation" class="active"><a target="_blank" href="http://<?php echo base_url('images/examples/uniq-sort.gif'); ?>">uniq</a></li>
  <li role="presentation" class="active"><a target="_blank" href="http://<?php echo base_url('images/examples/find.gif'); ?>">find</a></li>
  <li role="presentation" class="active"><a target="_blank" href="http://<?php echo base_url('images/examples/file.gif'); ?>">file</a></li>
  <li role="presentation" class="active"><a target="_blank" href="http://<?php echo base_url('images/examples/xxd2.gif'); ?>">xxd</a></li>
  <li role="presentation" class="active"><a target="_blank" href="http://<?php echo base_url('images/examples/compression.gif'); ?>">Compression</a></li>
</ul>
<p>Often times a CTF key will be hidden in a file system somewhere with the only thing separating you from it being a mass quantity of junk files/strings. So just what can we do here? Take a look at the commands below and see which ones you can employ</p>

<!-- GREP command  -->
<h3 id="grep">grep</h3>
<span class="col-md-5" >Command Structure: <kbd>grep [options] PATTERN [FILE...]</kbd></span>
<span class="col-md-4" >MAN Page: <a target="_blank" class="btn btn-xs btn-danger"href="http://unixhelp.ed.ac.uk/CGI/man-cgi?grep">Click Here To Read</a></span>
<pre class="pull-right col-md-3 language-none">
$ cat data.txt
...
72383562179944711268
71969900346231492778
01527098578201203644
08183625490011101090
69459818665223273653
78572779375278580718
69413178355495631882
15777025563555794618
80837424743658930232
63567444304155067573
72911871080873714796
key: 470119513221998
51175196137125935745
53634587096669842866
85238654437337849185
29174265715999359877
63164893553372949937
99288617984032219107
04022995884136711140
50723038697872938949
74496216035976919211
...</pre>
<p class="col-md-7"><br><kbd>grep</kbd> is extremely useful for searching files and directories for a word, string, etc. An example might look like this: Find the key, labeled "key:" in the string file data.txt. Certainly <kbd>cat</kbd> can be used and you can scroll through the file until you find the wanted line (example on right). What if, however, the file is a million lines long?  That might get hard to look through, especially if the strings are different lengths so on... Consider using the command example to the right.</p>
<pre class="language-none col-md-2">$ grep key data.txt
<font style="color: red">key</font>: 470119513221998
$</pre>
<p class="col-md-9">Level 1 down! What's next? How about a bunch of junk files. Lets say this for example...</p>
<pre class="col-md-9 language-none">
$ ls
file1.txt file2.txt file3.txt file4.txt file5.txt file6.txt file7.txt file8.txt file9.txt file10.txt file11.txt file12.txt file13.txt file14.txt file15.txt file16.txt file17.txt file18.txt file19.txt file20.txt file21.txt file22.txt file23.txt file24.txt file25.txt file26.txt file27.txt file28.txt file29.txt file30.txt file31.txt file32.txt file33.txt file34.txt file35.txt file36.txt file37.txt file38.txt file39.txt file40.txt file41.txt file42.txt file43.txt file44.txt file45.txt file46.txt file47.txt file48.txt file49.txt file50.txt file51.txt file52.txt file53.txt file54.txt file55.txt file56.txt file57.txt file58.txt file59.txt file60.txt file61.txt file62.txt file63.txt file64.txt file65.txt file66.txt file67.txt file68.txt file69.txt file70.txt file71.txt file72.txt file73.txt file74.txt file75.txt file76.txt file77.txt file78.txt file79.txt file80.txt file81.txt file82.txt file83.txt file84.txt file85.txt file86.txt file87.txt file88.txt file89.txt file90.txt file91.txt file92.txt file93.txt file94.txt file95.txt file96.txt file97.txt file98.txt file99.txt file100.txt
$ grep -r key .
file95.txt: <font style="color: red">key</font>: 470119513221998</pre>
<p>The magic is done here with the -r option which sets the grep command to recursive mode. This recurses through the given directory and greps every file. We specified the current directory, ., and file95.txt was the one containing our key!</p>
<a target="_blank" class="btn btn-primary col-md-1"href="http://<?php echo base_url('images/examples/grep.gif'); ?>">grep usage example</a>
<p class="col-md-8">The usage example located at the link on the right demonstrated the usage of the <kbd>grep</kbd> command in a Linux environment. The first command given is an <kbd>ls -l</kbd> which shows that the file data.txt is 262144 bytes in size - pretty big. I then use the command <kbd>grep happ data.txt</kbd> which searches for instances of the word "happ" in the file. It returns two along with the data next to them. </p>
<div class="clearfix"></div> <!-- cleanup the floats and divs. Allowing a fresh start with the next command-->

<!-- STRINGS command-->
<h3 id="strings">strings</h3>
<span class="col-md-3">Command Structure <kbd>strings [OPTIONS] [FILE...]</kbd></span>
<span class="col-md-3">MAN Page: <a target="_blank" class="btn btn-xs btn-danger" href="http://unixhelp.ed.ac.uk/CGI/man-cgi?strings">Click here to read</a></span>
<pre class="pull-right col-md-6 language-none">
$ less data.txt
B6>d^G+<A8>u<A7><D1><80><AF><B1><F6>A^Z<93><FA>(^V(%yRM^L<D5><B7><8B>=<B1><83>^Y<91><B4>{Y7<C6>^N4Al<F8><CB><89><DA><8B>IM<C4>7<84>TN<C0>l<E1><DF><85>zv<AB>&vW<9C>z-<DF>w<F4><99><B9><A2><F8>><89><BF><DF><D9><F7><A6><90>*<D4><AC><95>^X-V^M{9<92><F5>ESC>zT^C<94><E9><A1>saX<CE>^]<82><F7>^V<AE>?<91><AC><B6>
<CE>7<9A>^Zs<FC>M<AA><B8><81><E9><F2>5G<D9>k<F0>v<B1>^K<F7>lN<FB><B5><D1><94><EB>5|<EC>L<A5>b<D3>p^E^D<AC><9C>d<FC>$=<9E>^X<97><F6>*<84>2<AA><B5>^U=_[^F[/[<A6><E6><81><D9><BA>ozn^V<FA>&W<E6><9F>\<B0><85><83><KX-g<EB><B6><98><88>K<F3>7k<C4>m<AB><95><FF><D9><B8><F4>w28^FOv<81>^?<E4>5^R<B8><8E>"vX<F2><D0>^L
<9C>_<DA><CF>^Y<F3>?)<A5><9D>8b<8E><F2>V<E7>i<95><E1><C5>4^@<A6>zQ<BD>I'^C<E1>+<B9><B3>k<97>^Y"<C5>S<DC>/p<A7>c<DF><A8><A6><C4>_<89>^V<BE>t<E3><AD><AE>^OT<FC><B6><BD><EA><BD><EE><85>o^A<8E>^^^PkJ$^A<94>db<E4>w<DD>m^T<AD>Y^QW<95>^F<A4>^?`*,^SK^]<F2><82>g^X<DB>?<B6>1<BE> $<E6><B2><95><E6>O<A6>V<99>Lj<C8>
<EA><81><D1>t<B3>^W<FD><8C>^O<87><EC><D8><FA>^G<F7>^S<80><EB><C4>q\<C8>l<F5><AA>NBT<F7><88><E3><FF>R")^A<E3><F7><B2>G<E5><DF><87>8<C5><89>$<DF>I+<F7>E8J
<B8>^\<9D><DA><80>^P<EF><B4><E0><ED>;<89>[c^D GL<DC><EB><E0><C1>_v<C9><BB><F3>A"<BD>T<97><F3>X<A2><BC>S;<8A><8F><CD>
<DD><BE><CC><86>@^R2RO<DA><A5><82>`W<9A><D9>:?^L<F4><A1>^G<8F>V<93><D4>Y<C9><BA>3<B9><91><AE>L^K<DE>^Xh<AB>!<A3><D1>)<C9>s<BC>O<CA><EB><97><F4>.'-z<99>,L<E1>m<A1>Kz<D1>V<8A><EB><D3>D<CE><C7>^Nl^Q<D1><89><DE>^P4@<CF>^@<AD><C5>o<CA>^_*<AF><EE>!;<A8>r<D4><86><9F><CD>%&<CA><B9>'<8B>$<C3>1~{,<A9><C4>U_<A1>M
<C9>^B^X<F9>
^?^D`<91><C6>U<99><DD><8C><C0>X^Ut! <CE>M<D3>^G<E7>^L<F0><80>e^^s<D3>f4<BD><E7><B5><CA>^B^U<B9>E<82><E3><E6><BA>6<FF><9A><CE><D6>S<BF>n<E3>fv<C8><DD><F0><E9>sW^A<A3><F2> WX2<DB>,<E1><A7>D<A3><D4><FB><CF>ob<DD>^H<AA>};K,<<94><8F>^V<C0>V<D3><D4>^]^WK<CB><81><C2>QE<CE><D0>3<FF>^M<F5><8B>!<B4>^V<9E>}<AE>*y6
<CD>ESC<92><BC><D6><E7>f<92><C1><DE>Q4R<CD>^Q^K+<AE><AC><87>D<A5><DA>^F<F6>^C<DE><BC>E<AA><E8>^G<B7><A4><8A>    <CF>'Y<81>&79<B3>.<B8>^P<8A>xb<BB>^Gf^N^\<D3><CC><99>H<EA>^]e<F9>KiV<8E>^
z<E5><93><9E><C0><C5>1cF<F5>========== truKLdjsbJ5g7yyJ2X2R0o3a5HQJFuLk
<B7>^B<C4><DB>^<B6><F6><B4><CC>^F<F1><BB>^T<C8><B1><F1><BD><E8><F6>),^N<A1><8D>,<CE><A9><B4>kL<BA>6<DB>h^X<B6><8F>^P<A5>li<A7>y<8D><AD>u<E4><92><A4>X<C7>3<F1>d<F5>,<97>I<E4><F3><B8><FC><D4>Q<8E>2Y{<AA><C3>^B<8A>ESC2<9A><D3><FB><BF><A9>4^LS<C6><B6><91>^Y<A4><CB><9F>=^?Vw<83>d@<C2><FC>x<FA><AB><BE><D4>_<97><92>L<D8>b<92><D5><B9>eR<F9><95>}^\<A4><C1><E7><B4><EC><B4><F1>^\<D7><99><A4>d<9D>^N^Wi<C5><C1><92>H^Y<E2>@<E7>,|<F0><AC><F8>^W^?<A9><94><ED><C0><DD>e
<FA>    <D7><84>[<F0><E5><D9><E6>>TA^]^H<8E>G<C0><C8>}<9A>\<D7><83><E5>yY<F0><8C><82>#<D9>>1<ED><F1>^G<FC><E2><91>-'<93>Nqp@<CC>6<B6><AB>y<CA>.\<A0>=ESCN<CF><E2>a<AB><AC>E<A3><FC>:^^<E8>^D<DC><80><98>I^O<95><C4>^MZ<E2><DC><89>;^N<F3><82><AB>-(F<CE><9E><C8>ne<A6>ESC<DC>^^:<A4><B2><EA><FF>0<E7><96>ESC<FB>M
<EE>^N<EC><C8><DC><F7>W<BB><D7><BB>Z<BA>3<DD>+N^Q<BF><B4>v<AA>g<8F><EB>$^KG<D7><8D><CF>^M<89><B6>*[9<A0><F4>5(<92><E7><D1><83><8A><B9>w"#/6><D7>^L<E9>)
<88><F4>{<97>)<F2><F6><C0>}<ED><E6><9D><D1>^S={<DD><F3><89>^?^HQE++<8E>}<8A><9D>-'<F7>z{^R<90><94><9C>^Yml*<CB>^\<AB>[<AB>y'Q<F8>j<E4>q<E3><B5><9F>Q<FD>w<9E><D1>p<EE>j<B2><D8>|<FC>pi<84>{<96>^D<C5>Ax#<89>^L^Sy^W1+^\<F2><F9>:<8F><96>^C<82><D5><C3><84><AD>o<84>gg^V^B<E3>P<9A><97>^*<FD><9C><96><EC><89>^\<DA>^QYX<C6><89>zr<DA><B1>\ESC<E6><BB><CA><C7><A1>h<C7>Y<CE><88>t<B3><E9>WG2
...
</pre>
<p class="col-md-4"><br>
To illustrate the usefulness of this commands lets say we have the file shown on the far right. Looking at it closely you may notice an odd string in all of the junk, ========== tru... This is our target. Remember that the file is very large and continues on both sides with junk. I have chosen only a small segment of the file, the one that happens to have the key in it (for illustration purposes). The strings command with the file as its argument will return the readable strings in this file.
<kbd>strings data.txt</kbd>. As you can see, the binary and unreadable data in the file is removed and only the important objects are returned.</p>
<pre class="col-md-2 language-none">
$ strings data.txt
)HV1]X3
,yN&lt;
')UGY
k}Z,W
-;M1P
2[eh
Buz+FD
dw&lt;)
x.8d/
m$4d
yVJ\5V
xQ;@
#1/&quot;
0YMgc
\clH
*,E9
};;{W
Vq/_
4q1#
,^R,9
1*$T!
3/P?
kdJ_
&gt;$\:W
 ? d
d^G+
(%yRM
&lt;KX-g
.'-z
1~{,
 WX2
};K,&lt;
========== truKLdjsbJ5g7yyJ2X2R0o3a5HQJFuLk
Nqp@
w&quot;#/6&gt;
QE++
6?M	
V9p&gt;
Y22f
'WT$
v?4s
xp,b
ai2v&gt;/
.*VT
H%bY
a_cd
...
</pre>
<div class="clearfix"></div>

<!-- TR command-->
<h3 id="tr">tr</h3>
Command Structure: <kbd>tr [OPTION]... SET1 [SET2]</kbd><br><br>
MAN Page: <a target="_blank" class="btn btn-xs btn-danger"href="http://unixhelp.ed.ac.uk/CGI/man-cgi?tr">Click Here To Read</a>
<p></p>
<h3 id="base64">base64</h3>
<h3 id="sort">sort</h3>
<h3 id="uniq">uniq</h3>
<h3 id="find">find</h3>
<h3 id="file">file</h3>
<h3 id="xxd">xxd</h3>
<p>xxd allows, for the most part, the transversal between a hexdump and its binary file. </p>
<h3 id="file">Compression</h3>
<h2 id="pipes">Piping and Redirecting</h2>
<p>The commands above are extremely powerful, but some are hard to use by themselves. For example uniq will require a sort if the file you are searching is jumbled. Take a look at this documentation to learn what we can do to remedy this issue.</p>
        <h2 id="other">Misc. Useful Commands</h2>
        <hr />
        <h2>Compilation, Assembly, and Linking</h2>
        Compile C file (32 bit executable):
<pre><code>
$ gcc foo.c -o foo                      # 32-bit
$ gcc -m32 foo.c -o foo                 # 64-bit
$ gcc -m32 -B /home/mids/m164122/libc   # Michelson Labs
</code></pre>
        Compile C file (32 bit executable, security features disabled):
<pre><code>
$ gcc -fno-stack-protector -z execstack foo.c -o foo                      # 32-bit
$ gcc -fno-stack-protector -z execstack -m32 foo.c -o foo                 # 64-bit
$ gcc -fno-stack-protector -z execstack -m32 -B /home/mids/m164122/libc   # Michelson Labs
</code></pre>       
        Assemble file (shellcode to flat binary):
<pre><code>
$ nasm foo.asm -o foo
</code></pre>
        Assemble file (assembly program to ELF object file):
<pre><code>
$ nasm foo.asm -o foo.o -felf
</code></pre>
        Link assembly code (32 bit, using C runtime, e.g. main):
<pre><code>
$ gcc foo.o -o foo                                    # 32 bit machine
$ gcc -m32 foo.o -o foo                               # 64 bit machine
$ gcc -m32 -B /home/mids/m164122/libc foo.o -o foo    # Michelson Labs
</code></pre>
        Link assembly code (using system calls, e.g. _start):
<pre><code>
$ ld foo.o -o foo
</code></pre>
        <h2>Disassembly/Reverse Engineering</h2>
        Disassemble binary (ELF):
<pre><code>
$ objdump -d -Mintel foo &gt; foo.asm
</code></pre>
        Disassemble binary (flat binary):
<pre><code>
$ objdump -bbinary -mi386 -Mintel -D foo &gt; foo.asm
</code></pre>
        Show contents of binary, with load addresses:
<pre><code>
$ objdump -s foo &gt; foo.data
</code></pre>
        Check if the stack is executable:
<pre><code>
$ readelf -l foo       # Look at the flags field of the GNU_STACK header
</code></pre>
        Check executable section locations/permissions:
<pre><code>
$ readelf -S foo
</code></pre>
        Run program without ASLR (32 bit):
<pre><code>
$ setarch linux32 -R ./foo       # Run foo with ASLR off
$ setarch linux32 -R /bin/bash   # Run a shell, no ASLR for child progs
</code></pre>
        <h2>GDB Commands</h2>
        Set intel syntax:
<pre><code>
(gdb) set disassembly-flavor intel
</code></pre>
        Debug child processes (useful for debugging server processes):
<pre><code>
(gdb) set follow-fork-mode child
</code></pre>
        Show current instruction after each command:
<pre><code>
(gdb) display/i $pc
</code></pre>
        Step through a nop sled:
<pre><code>
(gdb) while *((unsigned char*)$eip) == 0x90
&gt; nexti
&gt; end
</code></pre>
        <h2>Remote Exploitation</h2>
        Send a payload:
<pre><code>
$ python -c 'print "A"*1024' | nc 127.0.0.1 1337
</code></pre>
        Make fifo (special file, FIFO queue):
<pre><code>
$ mkfifo fifo
</code></pre>
        Use a fifo to simulate a netcat shell listener (when nc -e is
        unsupported):
<pre><code>
$ /bin/sh -i &lt; fifo 2&gt;&amp;1 | nc -l 1337 &gt; fifo
</code></pre>
<?php endif; ?>
<?php
$this->load->view('templates/footer');
?>