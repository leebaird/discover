<?php
    require_once("common.php");

    if(empty($_SESSION['user'])) {
        header("Location: ../index.php");
        die("Redirecting to ../index.php");
    }
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Assessment Manager</title>
    <link rel="stylesheet" href="../public/resources/css/bootstrap.min.css">
    <script src="../public/resources/js/jquery.min.js"></script>
    <script src="../public/resources/js/bootstrap.min.js"></script>
    <script src="../public/resources/js/script.js"></script>
    <?php require_once "../includes/common.php"; ?>
    <link rel="stylesheet" href="../public/resources/css/jquery-ui.css">
    <script src="../public/resources/js/jquery-1.10.2.js"></script>
    <script src="../public/resources/js/jquery-ui.js"></script>
</head>

<style>
	body {
		background-color: White;
		margin-left: 40px;
		margin-right: 40px;
	}

	.navbar .navbar-nav {
		display: inline-block;
		float: none;
		vertical-align: top;
	}

	.navbar .navbar-collapse {
		text-align: center;
	}

	.navbar .navbar-right {
		display: inline-block;
		float: none;
		text-align: right;		
		vertical-align: top;
	}
</style>

<body id=<?php echo $bodyid ?>>

<div class="navbar navbar-inverse navbar-fixed-top" role="navigation">
	<div class="navbar-header">
		<a class="navbar-brand">Assessment Manager</a>
	</div>

	<div class="collapse navbar-collapse">
		<div class="container">
			<ul class="nav navbar-nav">
				<li><a href="../public/home.php">Home</a></li>
				<li><a href="../public/clients.php">Clients</a></li>
				<li><a href="../public/contacts.php">Contacts</a></li>
				<li><a href="../public/employees.php">Employees</a></li>
				<li><a href="../public/findings.php">Findings</a></li>
				<li><a href="../public/projects.php">Projects</a></li>
				<li class="dropdown"><a class="dropdown-toggle" data-toggle="dropdown" href="#">Vulnerabilities<span class="caret"></span></a>
					<ul class="dropdown-menu">
						<li><a href="../public/hostvulns.php">Host</a></li>
						<li><a href="../public/webvulns.php">Web</a></li>
					</ul>
				</li>
			</ul>

			<ul class="nav navbar-nav navbar-right">
				<li>
					<a href="../public/logout.php"><span class="glyphicon glyphicon-log-out"></span> Logout</a>
				</li>
			</ul>
		</div>
	</div>
</div>

<br><br>
