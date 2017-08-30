<?php
	$bodyid = "home";
	include "../includes/header.php";
	require_once("../includes/common.php");

    if(!empty($_POST)) {
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

        // If the user is changing their email address, we need to make sure that the new value does not
        // conflict with a value that is already in the database.
        if($_POST['email'] != $_SESSION['user']['email']) {
            $query = "SELECT 1 FROM users WHERE email = :email";
            $query_params = array(
                ':email' => $_POST['email']
            );

            try {
                $stmt = $db->prepare($query);
                $result = $stmt->execute($query_params);
            }

            catch(PDOException $ex) {
                // On a production website, you should not output $ex->getMessage().
                die("Failed to run query: " . $ex->getMessage());
            }

            $row = $stmt->fetch();
            if($row) {
                die("This email address is already in use.");
            }
        }

        // If the user entered a new password, we need to hash it and generate a fresh salt.
        if(!empty($_POST['password'])) {
            $salt = dechex(mt_rand(0, 2147483647)) . dechex(mt_rand(0, 2147483647));
            $password = hash('sha256', $_POST['password'] . $salt);
            for($round = 0; $round < 65536; $round++) {
                $password = hash('sha256', $password . $salt);
            }
        } else {
            // If the user did not enter a new password, we will not update their old one.
            $password = null;
            $salt = null;
        }

        // Initial query parameter values.
        $query_params = array( 
            ':email' => $_POST['email'], 
            ':user_id' => $_SESSION['user']['userID'], 
        );

        // If the user is changing their password, then we need parameter values for the new password hash
		// and salt.
        if($password !== null) {
            $query_params[':password'] = $password; 
            $query_params[':salt'] = $salt; 
        }

        // Note how this is only first half of the necessary update query. We will dynamically construct the
        // rest of it depending on whether or not the user is changing their password.
        $query = "UPDATE users SET email = :email 
        ";

        // If the user is changing their password, then we extend the SQL query to include the password, salt
		// columns, and parameter tokens.
        if($password !== null) {
            $query .= " 
                , password = :password 
                , salt = :salt 
            "; 
        }

        // Update the record for the current user.
        $query .= "WHERE userID = :user_id";

        try {
            $stmt = $db->prepare($query);
            $result = $stmt->execute($query_params);
        }

        catch(PDOException $ex) {
            // On a production website, you should not output $ex->getMessage().
            die("Failed to run query: " . $ex->getMessage());
        }

        // Now that the user's email address has changed, the data stored in the $_SESSION array is stale. We
        // need to update it so that it is accurate.
        $_SESSION['user']['email'] = $_POST['email'];

        header("Location: ../public/home.php");
        die("Redirecting to ../public/home.php");
    }
?>

<style>
	.vertical-center {
    	height: 80vh;
    	display: flex;
    	align-items: center;
    	justify-content: center;
	}
</style>

<div class="vertical-center">
	<div class="container col-md-5 col-md-offset-3">
	    <div class="panel panel-primary">
	        <div class="panel-heading">
	            <h3 class="panel-title">Edit Account</h3>
	        </div>
	        <div class="panel-body">

	        <form class="form-horizontal" action="edit_account.php" method="post" autocomplete="off">
	            <div class="form-group">
	                <label class="col-sm-4 control-label">Username</label>
	                <div class="col-sm-7">
	                    <input type="text" value="<?php echo htmlentities($_SESSION['user']['username'], ENT_QUOTES); ?>" class="form-control" readonly>
	                </div>
	            </div>

	            <div class="form-group">
	                <label class="col-sm-4 control-label">Email</label>
	                <div class="col-sm-7">
	                    <input type="text" name="email" value="<?php echo htmlentities($_SESSION['user']['email'], ENT_QUOTES); ?>" class="form-control">
	                </div>
	            </div>

	            <div class="form-group">
	                <label class="col-sm-4 control-label">New password</label>
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
	                <button class="btn btn-warning" type="submit">Update</button>
	                <a class="btn btn-default" href="../public/home.php">Back</a>
	            </div>
	        </form>

			</div>
		</div>
	</div>
</div>

<?php include '../includes/footer.php'; ?>
