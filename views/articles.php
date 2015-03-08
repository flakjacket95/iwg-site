<?php
$this->load->view('templates/header');
$i = 1;
?>
<?php foreach($test as $row):
$tags = explode(";", $row['tags']);
$links = explode(";", $row['links']);
?>
<?php if($single == false): ?>
	<div class="col-md-12 trng_article well">
<?php else: ?>
	<div class="col-md-4 trng_article well">
<?php endif; ?>
	<h1><?php echo $i . " " . $row['title']; ?></h1>
	<div class="col-md-12">
	<?php if($single == false): ?>
		<span class="col-md-1">Author: <?php echo $row['author']; ?></span>
		<span class="col-md-2">Last Edit: <?php echo $row['date']; ?></span>
		<span class="clearfix"></span>
		<span class="col-md-1">Tags: </span>
	<?php else: ?>
		<span class="col-md-5">Author: <?php echo $row['author']; ?></span>
		<span class="col-md-7">Last Edit: <?php echo $row['date']; ?></span>
		<span class="clearfix"></span>
		<span class="col-md-3">Tags: </span>
	<?php endif; ?>
		<?php foreach($tags as $tag): ?>
			<span class="tag label label-default"><?php echo $tag; ?></span>
		<?php endforeach; ?>
	</div>
	<div class="col-md-12"><hr></div>
	<?php if($single == false): ?>
		<p class="col-md-12"><?php echo html_entity_decode($row['content']); ?></p>
		<div class="col-md-12"><hr></div>
		<span class="col-md-1">Resource Links: </span>
	<?php else: ?>
		<span class="col-md-4">Resource Links: </span>
	<?php endif; ?>
	<?php foreach($links as $link): ?>
			<?php 
				$info = explode(",", $link)
			?>
			<a href="<?php echo $info[0]; ?>" target="_blank" class="btn btn-xs btn-success"><?php echo $info[1]; ?></a>
	<?php endforeach; ?>
	<?php if($single == true): ?>
	<span class="clearfix"></span><br>
	<a href="http://<?php echo site_url('welcome/article/' . $row['t_id']); ?>" class="col-md-12 btn btn-danger">Individual Article - Book-markable Page</a>
	<?php endif; ?>
</div>
<?php $i++; ?>
<?php endforeach; ?>
<pre>
<?php print_r ($test); ?>
</pre>
<?php
$this->load->view('templates/footer');
?>