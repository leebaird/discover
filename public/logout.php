<?php
	// First we execute our common code to connection to the database and start the session.
	require_once("../includes/common.php");

	// Unset all of the session variables.
	$_SESSION = array();

	if (ini_get("session.use_cookies")) {
	    $params = session_get_cookie_params();
	    setcookie(session_name(), '', time() - 42000,
	        $params["path"], $params["domain"],
	        $params["secure"], $params["httponly"]
	    );
	}

	// Finally, destroy the session.
	session_destroy();

	header("Location: ../index.php");
	die("Redirecting to: ../index.php");
?>
