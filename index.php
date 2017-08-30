<?php
    require("includes/common.php");

    // This variable will be used to re-display the user's username to them in the login form if they fail to
    // enter the correct password. It is initialized here to an empty value, which will be shown if the user
    // has not submitted the form.
    $submitted_username = '';

    // This if statement checks to determine whether the login form has been submitted. If it has, then the
    // login code is run, otherwise the form is displayed.
    if(!empty($_POST)) {
        $query = "SELECT userID, username, password, salt, email FROM users WHERE username = :username";

        // The parameter values.
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

        // This variable tells us whether the user has successfully logged in or not. We initialize it to
        // false, assuming they have not. If we determine that they have entered the right details, then we
        // switch it to true.
        $login_ok = false;

        // Retrieve the user data from the database. If $row is false, then the username they entered is not
		// registered.
        $row = $stmt->fetch();
        if($row) {
            // Using the password submitted by the user and the salt stored in the database, we now check to
            // see whether the passwords match by hashing the submitted password and comparing it to the
            // hashed version already stored in the database.
            $check_password = hash('sha256', $_POST['password'] . $row['salt']);
            for($round = 0; $round < 65536; $round++) {
                $check_password = hash('sha256', $check_password . $row['salt']);
            }

            if($check_password === $row['password']) {
                // If they do, then we flip this to true.
                $login_ok = true;
            }
        }

        // If the user logged in successfully, then we send them to the private members-only page. Otherwise,
        // we display a login failed message and show the login form again.
        if($login_ok) {
            // Here we are preparing to store the $row array into the $_SESSION by removing the salt and 
            // password values from it. Although $_SESSION is stored on the server-side, there is no reason
            // to store sensitive values in it unless you have to. Thus, it is best practice to remove these
            // sensitive values first.
            unset($row['salt']);
            unset($row['password']);

            // This stores the user's data into the session at the index 'user'. We will check this index on
            // the private members-only page to determine whether or not the user is logged in. We can also
            // use it to retrieve the user's details.
            $_SESSION['user'] = $row;

            header("Location: public/home.php");
            die("Redirecting to: public/home.php");
        } else {
            print("Login Failed.");
        }
    }
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Assessment Manager</title>	
    <link href="public/resources/css/bootstrap.min.css" rel="stylesheet">
</head>

<style>	
	body {
  		background-color: #d6d6d6;
		padding-top: 40px;
		padding-bottom: 40px;
	}

	.vertical-center {
    	height: 80vh;
    	display: flex;
    	align-items: center;
	}

	.container {
		max-width: 300px;
	}
</style>

<body>

<div class="vertical-center">
	<div class="container">
	    <form class="form-signin" action="index.php" method="post" autocomplete="off">
	        <h3 class="form-signin-heading">Please sign in</h3>
	        <input type="text" class="form-control" name="username" placeholder="Username">
	        <input type="password" class="form-control" name="password" placeholder="Password">
			<br>
	        <button class="btn btn-lg btn-primary btn-block" type="submit">Sign in</button>
			Need an accout? <a href="includes/register.php">Register</a>
	    </form>
	</div>
</div>
