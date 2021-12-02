<?php

	$connection = mysqli_connect("localhost", "root", "", "sqli");

	if (!$connection)
	{
		die ("Failed to connect to MySQL: <strong>" . mysqli_connect_error() . "</strong>");
	}
?>