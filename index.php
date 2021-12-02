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
          
          <li class="dropdown">
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

      <div class="jumbotron">
        <h2><strong>SQL Injection Detection and prevention</h2>
        <h3>ISAA Project</h3>

      </div>
      <div class="jumbotron">
      <h2><strong>Team</h2>
      <ol>
          <li>Shreyash vardhan 19BIT0001</li>
          <li>Ronak sinha 19BIT0019</li>
        </ol>

      </div>  
     

     

    </div> <!-- /container -->

    <script src="https://ajax.googleapis.com/ajax/libs/jquery/1.11.0/jquery.min.js"></script>
    <script src="js/bootstrap.min.js"></script>
  </body>
</html>
