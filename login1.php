<?php
require "db_connect.php";
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    
    <title>SQL Injection Demo</title>

    <link href="css/bootstrap.min.css" rel="stylesheet">
    <link href="css/style.css" rel="stylesheet">
</head>

<body>

    <div class="container">
        <div class="header hidden-xs">
            <ul class="nav nav-pills pull-right">
                <li class="active dropdown">
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

        <h3 class="text-center"><span class="label label-warning">
                Secure Standard Login</span></h3><br>

        <?php
        if (@$_GET['attempt'] != 1) {
        ?>

            <div class="row">
                <div class="col-sm-offset-2 col-sm-8">
                    <form class="form-horizontal" role="form" action="login1.php?attempt=1" method="POST">
                        <div class="form-group">
                            <label for="inputEmail3" class="col-sm-2 control-label">Username</label>
                            <div class="col-sm-8">
                                <input name="username" type="text" class="form-control" id="inputEmail3" placeholder="Username">
                            </div>
                        </div>
                        <div class="form-group">
                            <label for="inputPassword3" class="col-sm-2 control-label">Password</label>
                            <div class="col-sm-8">
                                <input name="password" type="text" class="form-control" id="inputPassword3" placeholder="Password">
                            </div>
                        </div>
                        <div class="form-group">
                            <div class="col-sm-offset-2 col-sm-10">
                                <button type="submit" class="btn btn-default">Sign in</button>
                            </div>
                        </div>
                    </form>
                </div>
            </div>

            <?php
        } else {
            $username = $_POST['username'];
            $password = $_POST['password'];

            $query = sprintf(
                "SELECT * FROM users WHERE username = '%s' AND password = '%s';",
                $username,
                $password
            );

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
                    $p = ($d * $p + ord($pat[$i])) % $q;
                    $t = ($d * $t + ord($txt[$i])) % $q;
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
            function checkBooleanBased($password)
            {
                $q = 101;
                // Function Call
                $pat = array("'", ";", "#", "=", "or", "||", ">", ">=", "<", "<=", "<>", "!=");
                $len = count($pat);
                for ($i = 0; $i < $len; $i++) {
                    if (search($pat[$i], $password, $q) > 0) {
                        return false;
                    }
                }
                return true;
            }

            //Union Based SQLIA
            function checkUnionBased($password)
            {
                $q = 101;
                // Function Call
                $pat = array("'", "union", "select", "from", "#");
                $len = count($pat);
                for ($i = 0; $i < $len; $i++) {
                    if (search($pat[$i], $password, $q) > 0) {
                        return false;
                    }
                }
                return true;
            }

            //batch query

            function checkBatchQuery($password)
            {
                $q = 101;
                // Function Call
                $pat = array("'", ";", "#", ";", "delete", "drop", "insert", "truncate", "update", "select", "alter");
                $len = count($pat);
                for ($i = 0; $i < $len; $i++) {
                    if (search($pat[$i], $password, $q) > 0) {
                        return false;
                    }
                }
                return true;
            }

            //check Like based 
            function checkLikeBased($password)
            {
                $q = 101;
                // Function Call
                $pat = array("'", "like", "%", "#");
                $len = count($pat);
                for ($i = 0; $i < $len; $i++) {
                    if (search($pat[$i], $password, $q) > 0) {
                        return false;
                    }
                }
                return true;
            }

            //Check XSS
            function checkXSS($password)
            {
                $q = 101;
                // Function Call
                $pat = array("</script>", "'", "<script>");
                $len = count($pat);
                for ($i = 0; $i < $len; $i++) {
                    if (search($pat[$i], $password, $q) > 0) {
                        return false;
                    }
                }
                return true;
            }

            // echo $ok;
            if (checkBooleanBased($password) and 
            checkBatchQuery($password) and
            checkUnionBased($password) and 
            checkXSS($password) and
            checkLikeBased($password)
            ){
                $result = mysqli_query($connection, $query);
            }
            if (@$result != NULL and @$result->num_rows > 0) {
                echo "<p class=\"text-center\">Authenticated as <strong>" . $username . "</strong></p>";
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
            ?>
                <div class="row">
                    <div class="col-sm-12">
                        <div class="highlight">
                            <pre>
    SQL injection Attack detected
    </pre>
                            <pre>
    MAC address of the attacker <?= GetMAC(); ?>
    </pre>
                            <pre>
    IP Address of the attacker <?= get_client_ip(); ?>
    </pre>
                        </div>
                    </div>
                </div>
            <?php

                // echo "<p class=\"text-center\">Wrong username/password combination.</p>";
            }
            ?>

            <hr>
        <?php } ?>
       
        <script src="https://ajax.googleapis.com/ajax/libs/jquery/1.11.0/jquery.min.js"></script>
        <script src="js/bootstrap.min.js"></script>
</body>

</html>