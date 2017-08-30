<?php
    $username = "root";
    $password = "";
    $host = "localhost";
    $dbname = "assessment_manager";

	// For login and register only.
    $db = new PDO("mysql:host={$host};dbname={$dbname}", $username, $password);
    if (!$db) {
		die ("DB connection failed. " . mysql_error());    	
    }
    else {
    	print("\nDB is OK. ");
    	$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    }

	// Create a db connection.
	$connection = mysqli_connect($host, $username, $password, $dbname);

	// Test if the connection occurred.
	if (!$connection) {
		die ("DB connection failed. " . mysql_error());
	}
    else {
    	print("\nConnection is OK. ");
    }

	function confirm_query($result) {
		if (!$result) {
			die ("DB query failed. " . mysql_error());
		}
	}

    session_start();
