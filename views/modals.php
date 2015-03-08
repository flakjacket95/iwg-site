<div class="modal fade" id="myModal" tabindex="-1" role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
        <button type="button" class="close" data-dismiss="modal"><span aria-hidden="true">&times;</span><span class="sr-only">Close</span></button>
        <h4 class="modal-title" id="myModalLabel">OBJDUMPME</h4>
      </div>
      <div class="modal-body">
        What is the instruction mnemonic of the 10th instruction in main in <a class="btn btn-xs btn-info" href="http://<?php echo base_url('files/cyberstakes/objdumpme'); ?>">this</a> binary? For example, the mnemonic for '804850f: 8d 83 00 ff ff ff lea -0x100(%ebx),%eax' is just 'lea'.
        <br />
        Attached Files:
        <a class="btn btn-info"  href="http://<?php echo base_url('files/cyberstakes/objdumpme'); ?>">objdumpme</a>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
        <!--<button type="button" class="btn btn-primary">Save changes</button>-->
      </div>
    </div>
  </div>
</div>

<div class="modal fade" id="myModal2" tabindex="-1" role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
        <button type="button" class="close" data-dismiss="modal"><span aria-hidden="true">&times;</span><span class="sr-only">Close</span></button>
        <h4 class="modal-title" id="myModalLabel">READASM</h4>
      </div>
      <div class="modal-body">
        At the end of this sequence of instructions, how many bytes separate esp and the stored return address on the program's stack? Assume that we called this function using standard 32-bit x86 calling conventions.
        <br />
        Instructions:
<pre style='color:#d1d1d1;background:#333333;'>0804847c <span style='color:#d2cd86; '>&lt;</span><span style='color:#e34adc; '>functioname:</span><span style='color:#d2cd86; '>></span>
<span style='color:#e34adc; '>804847c:</span>     <span style='color:#e66170; font-weight:bold; '>push</span> <span style='color:#d2cd86; '>%</span><span style='color:#d0d09f; '>ebp</span>
<span style='color:#008c00; '>804847d</span><span style='color:#d2cd86; '>:</span>     <span style='color:#e66170; font-weight:bold; '>mov</span> <span style='color:#d2cd86; '>%</span><span style='color:#d0d09f; '>esp</span><span style='color:#d2cd86; '>,</span><span style='color:#d2cd86; '>%</span><span style='color:#d0d09f; '>ebp</span>
<span style='color:#e34adc; '>804847f:</span>     <span style='color:#e66170; font-weight:bold; '>sub</span> $<span style='color:#00a800; '>0x3c</span><span style='color:#d2cd86; '>,</span><span style='color:#d2cd86; '>%</span><span style='color:#d0d09f; '>esp</span>
<span style='color:#008c00; '>8048482</span><span style='color:#d2cd86; '>:</span>     movl $<span style='color:#00a800; '>0x0</span><span style='color:#d2cd86; '>,</span><span style='color:#00a800; '>0x4</span><span style='color:#d2cd86; '>(</span><span style='color:#d2cd86; '>%</span><span style='color:#d0d09f; '>esp</span><span style='color:#d2cd86; '>)</span>
<span style='color:#e34adc; '>804848a:</span>     movl $<span style='color:#00a800; '>0x8048580</span><span style='color:#d2cd86; '>,</span><span style='color:#d2cd86; '>(</span><span style='color:#d2cd86; '>%</span><span style='color:#d0d09f; '>esp</span><span style='color:#d2cd86; '>)</span></pre>
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
        <h4 class="modal-title" id="myModalLabel">CRASHME1</h4>
      </div>
      <div class="modal-body">
        A vulnerable service is running on shell.cyberstakesonline.com:50125. If you can crash it, it will yield the key. Source is available <a class="btn btn-xs btn-info" target="_blank" href="http://<?php echo base_url('files/cyberstakes/crashme1.c'); ?>" >here</a>.
        <br />
        Note:
        The source will always be available. While you may not be able to access the service running at cyberstakes, you can solve this problem conceptually.<br>
        Attached Files:
        <a class="btn btn-info" target="_blank" href="http://<?php echo base_url('files/cyberstakes/crashme1.c'); ?>" >C Source</a>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
      </div>
    </div>
  </div>
</div>

<div class="modal fade" id="clientside" tabindex="-1" role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
        <button type="button" class="close" data-dismiss="modal"><span aria-hidden="true">&times;</span><span class="sr-only">Close</span></button>
        <h4 class="modal-title" id="myModalLabel">Client Side Authentication</h4>
      </div>
      <div class="modal-body">
        Why don't we trust Client Side Scripts for authentication? Check this out <a class="btn btn-xs btn-info" target="_blank" href="http://<?php echo base_url('files/cyberstakes/web/clientsideauth/'); ?>">Get in.</a>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
      </div>
    </div>
  </div>
</div>

<div class="modal fade" id="php1" tabindex="-1" role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
        <button type="button" class="close" data-dismiss="modal"><span aria-hidden="true">&times;</span><span class="sr-only">Close</span></button>
        <h4 class="modal-title" id="myModalLabel">PHP 1</h4>
      </div>
      <div class="modal-body">
        Try your luck: <a class="btn btn-xs btn-info" target="_blank" href="http://<?php echo base_url('files/cyberstakes/web/php1/'); ?>">Luck Game.</a>
      <br><br>
      Attached Files: <a class="btn btn-xs btn-info" target="_blank" href="http://<?php echo base_url('files/cyberstakes/web/php1/index.txt'); ?>">PHP Source</a>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
      </div>
    </div>
  </div>
</div>

<div class="modal fade" id="php2" tabindex="-1" role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
        <button type="button" class="close" data-dismiss="modal"><span aria-hidden="true">&times;</span><span class="sr-only">Close</span></button>
        <h4 class="modal-title" id="myModalLabel">PHP 2</h4>
      </div>
      <div class="modal-body">
        File reading: <a class="btn btn-xs btn-info" target="_blank" href="http://<?php echo base_url('files/cyberstakes/web/php2/'); ?>">Super Secret File Viewer.</a>
      <br><br>
      Attached Files: <a class="btn btn-xs btn-info" target="_blank" href="http://<?php echo base_url('files/cyberstakes/web/php2/index.txt'); ?>">PHP Source</a>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
      </div>
    </div>
  </div>
</div>

<div class="modal fade" id="php3" tabindex="-1" role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
        <button type="button" class="close" data-dismiss="modal"><span aria-hidden="true">&times;</span><span class="sr-only">Close</span></button>
        <h4 class="modal-title" id="myModalLabel">PHP 3</h4>
      </div>
      <div class="modal-body">
        Unsolvable Puzzle: <a class="btn btn-xs btn-info" target="_blank" href="http://<?php echo base_url('files/cyberstakes/web/php3/'); ?>">Puzzle.</a>
        <br><br>
        Attached Files: <a class="btn btn-xs btn-info" target="_blank" href="http://<?php echo base_url('files/cyberstakes/web/php3/index.txt'); ?>">PHP Source</a>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
      </div>
    </div>
  </div>
</div>

<div class="modal fade" id="bkplev6" tabindex="-1" role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
        <button type="button" class="close" data-dismiss="modal"><span aria-hidden="true">&times;</span><span class="sr-only">Close</span></button>
        <h4 class="modal-title" id="myModalLabel">Brigham Circle</h4>
      </div>
      <div class="modal-body">
        Sanitization is hard, lets use regexp!
        <br><br>
        Attached Files: <a class="btn btn-xs btn-info" target="_blank" href="http://<?php echo base_url('files/bkp/school-bus/brigham-circle/index.php'); ?>">Site Here</a>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
      </div>
    </div>
  </div>
</div>

<div class="modal fade" id="bkplev2" tabindex="-1" role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
        <button type="button" class="close" data-dismiss="modal"><span aria-hidden="true">&times;</span><span class="sr-only">Close</span></button>
        <h4 class="modal-title" id="myModalLabel">Symphony</h4>
      </div>
      <div class="modal-body">
        A less than four characters number, bigger than 999?Maybe the bug is elsewhere.
        <br><br>
        Attached Files: <a class="btn btn-xs btn-info" target="_blank" href="http://<?php echo base_url('files/bkp/school-bus/symphony/index.php'); ?>">Site Here</a>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
      </div>
    </div>
  </div>
</div>