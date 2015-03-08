Welcome to the lucky lottery!
<br>
<form action="index.php">
How lucky are you feeling? 
<br><input type="text" name="luck">
<input type="submit" value="Play">
</form>

<?php

$flag = "Congrats! You solved it.";

if (isset($_GET['luck'])) {
  if (strcmp($_GET['luck'],md5(openssl_random_pseudo_bytes(128))) == 0) {
    echo "Wow, you really are lucky!";
    echo "<br>";
    echo "key:{".$flag."}";
  }
  else {
    echo "Better luck next time ;) ";
  }
}
?>
