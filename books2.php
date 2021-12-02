<?php 
    require "db_connect.php";
?>
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="description" content="SQL Injection demo">
    <meta name="author" content="Francesco Borzì">

    <title>SQL Injection Demo</title>

    <link href="css/bootstrap.min.css" rel="stylesheet">
    <link href="css/style.css" rel="stylesheet">
  </head>

  <body>

    <div class="container">
      <div class="header hidden-xs">
        <ul class="nav nav-pills pull-right">
          <li class="dropdown">
            <a href="#" class="dropdown-toggle" data-toggle="dropdown">Standard Login<b class="caret"></b></a>
            <ul class="nav dropdown-menu">
              <li><a href="login1.php">Secure</a></li>
              <li><a href="login2.php">Vulnerable</a></li>
            </ul>
          </li>
          
          <li class="active dropdown">
            <a href="#" class="dropdown-toggle" data-toggle="dropdown">Search<b class="caret"></b></a>
            <ul class="nav dropdown-menu">
              <li><a href="books1.php">Vulnerable</a></li>
              <li><a href="books2.php">Secure</a></li>
            </ul>
          </li>
          
        </ul>
		<h3 class="text-muted"><a href="index.php">SQL-Injection Demo</a></h3>
      </div>
      <?php include("mobile-navbar.php"); ?>
      
      <h3 class="text-center"><span class="label label-success">
Secure Search</span></h3><br>
      
      <div class="row">
        <div class="col-sm-10">
          <form class="form-inline" role="form" action="books2.php" method="GET">
            <div class="form-group">
              <label class="sr-only" for="exampleInputEmail2">Book title</label>
              <input type="text" name="title" class="form-control" placeholder="Book title">
            </div>
            <div class="form-group">
              <label class="sr-only" for="exampleInputPassword2">Book author</label>
              <input type="text" name="author" class="form-control"placeholder="Book author">
            </div>
            <button type="submit" class="btn btn-success">Search</button>
          </form>
        </div>
        <div class="col-sm-2">
          <span class="visible-xs">&nbsp;</span>
          <a href="books2.php?all=1"><button type="button" class="btn btn-info">All books</button></a>
        </div>
      </div>
      
      <br>
      
     
      <?php
      $query=null;
       if (@$_GET['all'] == 1)
       {
           $query = "SELECT * FROM books;";
       }
       else if (@$_GET['title'] || @$_GET['author']){
       $d = 256;
       $ok = 1;

       function search($pat, $txt, $q)
       {
           $M = strlen($pat);
           $N = strlen($txt);
           $i=0;
           $j=0;
           $p = 0; // hash value 
           // for pattern
           $t = 0; // hash value 
           $h = 1;
           $d = 1;

           for ($i = 0; $i < $M - 1; $i++)
               $h = ($h * $d) % $q;

           for ($i = 0; $i < $M; $i++) {
               $p = ($d * $p + @ord($pat[$i])) % $q;
               $t = ($d * $t + @ord($txt[$i])) % $q;
           }
           for ($i = 0; $i <= $N - $M; $i++) {

               if ($p == $t) {

                   for ($j = 0; $j < $M; $j++) {
                       if ($txt[$i + $j] != $pat[$j])
                           break;
                   }

                   if ($j == $M)
                       return $i;
               }

               if ($i < $N - $M) {
                   $t = ($d * ($t - (ord($txt[$i])) * $h) + ord($txt[$i + $M])) % $q;


                   if ($t < 0)
                       $t = ($t + $q);
               }
           }
       }

       // Boolean based SQLIA
       $author=$_GET['author'];
       function checkBooleanBased($author)
       {
           $q = 101;
           // Function Call
           $pat = array("'", ";", "#", "=", "or", "||", ">", ">=", "<", "<=", "<>", "!=");
           $len = count($pat);
           for ($i = 0; $i < $len; $i++) {
               if (search($pat[$i], $author, $q) > 0) {
                   return false;
               }
           }
           return true;
       }

       //Union Based SQLIA
       function checkUnionBased($author)
       {
           $q = 101;
           // Function Call
           $pat = array("'", "UNION", "select", "from", "#");
           $len = count($pat);
           for ($i = 0; $i < $len; $i++) {
               if (search($pat[$i], $author, $q) > 0) {
                   return false;
               }
           }
           return true;
       }

       //batch query

       function checkBatchQuery($author)
       {
           $q = 101;
           // Function Call
           $pat = array("'", ";", "#", ";", "delete", "drop", "insert", "truncate", "update", "select", "alter");
           $len = count($pat);
           for ($i = 0; $i < $len; $i++) {
               if (search($pat[$i], $author, $q) > 0) {
                   return false;
               }
           }
           return true;
       }

       //check Like based 
       function checkLikeBased($author)
       {
           $q = 101;
           // Function Call
           $pat = array("'", "like", "%", "#");
           $len = count($pat);
           for ($i = 0; $i < $len; $i++) {
               if (search($pat[$i], $author, $q) > 0) {
                   return false;
               }
           }
           return true;
       }

       //Check XSS
       function checkXSS($author)
       {
           $q = 101;
           // Function Call
           $pat = array("</script>", "'", "<script>");
           $len = count($pat);
           for ($i = 0; $i < $len; $i++) {
               if (search($pat[$i], $author, $q) > 0) {
                   return false;
               }
           }
           return true;
       }

       // echo $ok;
       if ( 
       checkUnionBased($author) and 
       checkXSS($author) and
       checkLikeBased($author)
       ){
         echo "inje";
        $query = sprintf("SELECT * FROM books WHERE title = '%s' OR author = '%s';",
        $_GET['title'],
        $_GET['author']);
           $result = mysqli_query($connection, $query);
       }
       if (@$result != NULL and @$result->num_rows > 0) {
           
       } else {
             function GetMAC()
             {
                 ob_start();
                 system('getmac');
                 $Content = ob_get_contents();
                 ob_clean(); 
                 return substr($Content, strpos($Content, '\\') - 20, 17);
             }
             function get_client_ip()
             {
                 $ipaddress = '';
                 if (isset($_SERVER['HTTP_CLIENT_IP']))
                     $ipaddress = $_SERVER['HTTP_CLIENT_IP'];
                 else if (isset($_SERVER['HTTP_X_FORWARDED_FOR']))
                     $ipaddress = $_SERVER['HTTP_X_FORWARDED_FOR'];
                 else if (isset($_SERVER['HTTP_X_FORWARDED']))
                     $ipaddress = $_SERVER['HTTP_X_FORWARDED'];
                 else if (isset($_SERVER['HTTP_FORWARDED_FOR']))
                     $ipaddress = $_SERVER['HTTP_FORWARDED_FOR'];
                 else if (isset($_SERVER['HTTP_FORWARDED']))
                     $ipaddress = $_SERVER['HTTP_FORWARDED'];
                 else if (isset($_SERVER['REMOTE_ADDR']))
                     $ipaddress = $_SERVER['REMOTE_ADDR'];
                 else
                     $ipaddress = 'UNKNOWN';
                 return $ipaddress;
             }
         
        }
      }
        if ($query != null)
		{
			$result = mysqli_query($connection, $query);
      ?>
      <table class="table table-bordered">
      <tr>
        <th>#ID</th>
        <th>Title</th>
        <th>Author</th>
      </tr>
      <?php
			while (($row = mysqli_fetch_row($result)) != null)
			{

        
        
        
				printf("<tr><td>%s</td><td>%s</td><td>%s</td></tr>", $row[0], $row[1], $row[2]);
			}
		}else{
      ?>
      <div class="row">
                    <div class="col-sm-12">
                        <div class="highlight">
                            <pre>
    SQL injection Attack detected
    </pre>
                            <pre>
    MAC address of the attacker <?= @GetMAC(); ?>
    </pre>
                            <pre>
    IP Address of the attacker <?= @get_client_ip(); ?>
    </pre>
                        </div>
                    </div>
                </div>
                
    <?php }?>
      
      </table>
      
      <hr>
      <div class="row">
        <div class="col-sm-12">
          <h4>Query Executed:</h4>
        </div>
      </div>
      
      <div class="row">
        <div class="col-sm-12">
          <div class="highlight">
            <pre><?= $query ?></pre>
          </div>
        </div>
      </div>
      
      <hr>
      
      <br>

 

    </div> 

    <script src="https://ajax.googleapis.com/ajax/libs/jquery/1.11.0/jquery.min.js"></script>
    <script src="js/bootstrap.min.js"></script>
  </body>
</html>
