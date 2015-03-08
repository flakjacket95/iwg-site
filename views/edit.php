<?php
$this->load->view('templates/header');
?>
<h1>Insert an Article</h1>
<span style="color: red;">
</span>
<form method="post" id="article" action="http://<?php echo site_url('welcome/ins_article'); ?>" >
		<div class="form-group">
    		<div class="col-md-6 input-group">
     			<div class="input-group-addon">Title</div>
      			<input required type="text" class="form-control" name="title">
    		</div>
        <span id="helpBlock" class="help-block">Displayed as a header 1 element.</span>
 		</div>
    <div class="form-group">
        <div class="col-md-6 input-group">
          <div class="input-group-addon">Content</div>
            <textarea required class="form-control" rows="15" form="article" name="content"></textarea>
        </div>
        <span id="helpBlock" class="help-block">HTML is valid, script tags and js references will be removed. Use bootstrap classes for styling</span>
    </div>
    <div class="form-group">
        <div class="col-md-6 input-group">
          <div class="input-group-addon">Tags</div>
            <input required type="text" placeholder="tag1;tag2;tag3" class="form-control" name="tags">
        </div>
        <span id="helpBlock" class="help-block">Input quick tags, semi-colon separated</span>
    </div>
    <div class="form-group">
        <div class="col-md-6 input-group">
          <div class="input-group-addon">Links</div>
            <input type="text" placeholder="URL1,LABEL1;URL2,LABEL2;URL3,LABEL3" class="form-control" name="links">
        </div>
        <span id="helpBlock" class="help-block">Links can be included in the content but these are for quick reference and are displayed in an easily accessed location. The formatting is specific, URL,Label;URL,label. For example, http://www.google.com,Google will produce <a href="http://www.google.com">Google</a></span>
    </div>
 		<div class="form-group">
    		<div class="col-md-6 input-group">
      			<input type="submit" class="col-md-12 btn btn-success" id="submit" name="submit" value="Submit Article">
    		</div>
 		</div>
 		</form>
<?php
$this->load->view('templates/footer');
?>