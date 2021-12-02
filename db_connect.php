<?php

	$connection = mysqli_connect("database-1.cwn5hv7y1ith.us-east-2.rds.amazonaws.com", "admin", "adminpass", "sqli");

	if (!$connection)
	{
		die ("Failed to connect to MySQL: <strong>" . mysqli_connect_error() . "</strong>");
	}
?>