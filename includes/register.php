<?php
	require_once("common.php");

    if(!empty($_POST)) {
        if(empty($_POST['username'])) {
            die("Please enter a username.");
        }

        if(empty($_POST['password'])) {
            die("Please enter a password.");
        }

		if(strlen($_POST['password']) < 12) {
		    die("Your password is too short. The minimum length is 12 characters.");
		}

		if(($_POST['password']) != ($_POST['password2'])) {
		    die("Your passwords do not match.");
		}

		if(!preg_match("#[A-Z]+#", ($_POST['password']))) {
			die("Your password must contain at least one uppercase letter.");
		}

		if(!preg_match("#[a-z]+#", ($_POST['password']))) {
			die("Your password must contain at least one lowercase letter.");
		}

		if(!preg_match("#[0-9]+#", ($_POST['password']))) {
			die("Your password must contain at least one number.");
		}

		if(!preg_match("#[\W]+#", ($_POST['password']))) {
			die("Your password must contain at least one special character.");
		}

        if(!filter_var($_POST['email'], FILTER_VALIDATE_EMAIL)) {
            die("Invalid email address.");
        }

        // Check if the username is already in use.
        $query = "SELECT 1 FROM users WHERE username = :username";

        // This contains the definitions for any special tokens that we place in the SQL query.
        $query_params = array(
            ':username' => $_POST['username']
        );

        try {
            $stmt = $db->prepare($query);
            $result = $stmt->execute($query_params);
        }

        catch(PDOException $ex) {
            // On a production website, you should not output $ex->getMessage().
            die("Failed to run query: " . $ex->getMessage());
        }

        // The fetch() method returns an array representing the "next" row from the selected results, or
        // false if there are no more rows to fetch.
        $row = $stmt->fetch();

        // If a row was returned, then we know a matching username was found in the database already and we
        // should not allow the user to continue.
        if($row) {
            die("This username is already in use.");
        }

        // Perform the same type of check for the email address, in order to ensure that it is unique.
        $query = "SELECT 1 FROM users WHERE email = :email";

        $query_params = array(
            ':email' => $_POST['email']
        );

        try {
            $stmt = $db->prepare($query);
            $result = $stmt->execute($query_params);
        }

        catch(PDOException $ex) {
            die("Failed to run query: " . $ex->getMessage());
        }

        $row = $stmt->fetch();

        if($row) {
            die("This email address is already in use.");
        }

        $query = "INSERT INTO users (modified, username, email, password, salt) VALUES (now(), :username, :email, :password, :salt)";

        // A salt is randomly generated here to protect against brute force and rainbow table attacks.
        $salt = dechex(mt_rand(0, 2147483647)) . dechex(mt_rand(0, 2147483647));

        // Hash the password with the salt so that it is securely stored in the database.
        $password = hash('sha256', $_POST['password'] . $salt);

        // Hash the hash value 65,536 more times to protect against brute force attacks.
        for($round = 0; $round < 65536; $round++) {
            $password = hash('sha256', $password . $salt);
        }

        $query_params = array(
            ':username' => $_POST['username'],
            ':password' => $password,
            ':salt' => $salt,
            ':email' => $_POST['email']
        );

        try {
            // Execute the query to create the user.
            $stmt = $db->prepare($query);
            $result = $stmt->execute($query_params);
        }

        catch(PDOException $ex) {
            // On a production website, you should not output $ex->getMessage().
            die("Failed to run query: " . $ex->getMessage());
        }

		// Postfix not configured yet.
		$to = "leebaird@gmail.com";
		$subject = "New user registration.";
		$message = "A new user has requested an account.";
		mail($to,$subject,$message);

        header("Location: ../index.php");
        die("Redirecting to ../index.php");
    }
?>

<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="../public/resources/css/bootstrap.min.css">
    <script src="../public/resources/js/jquery.min.js"></script>
    <script src="../public/resources/js/bootstrap.min.js"></script>
</head>

<style>
	.vertical-center {
    	height: 80vh;
    	display: flex;
    	align-items: center;
    	justify-content: center;
	}
</style>

<body>

<div class="vertical-center">
	<div class="container col-md-5 col-md-offset-3">
	    <div class="panel panel-primary">
	        <div class="panel-heading">
	            <h3 class="panel-title">Register Account</h3>
	        </div>
	        <div class="panel-body">

	        <form class="form-horizontal" action="register.php" method="post" autocomplete="off">
	            <div class="form-group">
	                <label class="col-sm-4 control-label">Username</label>
	                <div class="col-sm-7">
						<input type="text" name="username" value="" class="form-control">
	                </div>
	            </div>

	            <div class="form-group">
	                <label class="col-sm-4 control-label">Email</label>
	                <div class="col-sm-7">
						<input type="text" name="email" value="" class="form-control">
	                </div>
	            </div>

	            <div class="form-group">
	                <label class="col-sm-4 control-label">Password</label>
	                <div class="col-sm-7">
	                    <input type="password" name="password" value="" class="form-control">
	                </div>
	            </div>

	            <div class="form-group">
	                <label class="col-sm-4 control-label">Re-enter password</label>
	                <div class="col-sm-7">
	                    <input type="password" name="password2" value="" class="form-control">
	                </div>
	            </div>

	            <div class="form-group">
	                <label class="col-sm-4 control-label">Requirements</label>
	                <div class="col-sm-7">
						Uppercase<br>
						Lowercase<br>
						Number<br>
						Special character<br>
						Minimum 12 characters in length.
	                </div>
	            </div>

	            <div class="form-actions">
	                <button class="btn btn-warning" type="submit">Register</button>
	                <a class="btn btn-default" href="../index.php">Back</a>
	            </div>
	        </form>

			</div>
		</div>
	</div>
</div>
