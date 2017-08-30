<?php
	$bodyid = "home";
	include "../includes/header.php";
	require_once("../includes/common.php");
?>

<br>

<div class="vertical-center">
	<div class="container col-md-8 col-md-offset-2">
		<br><br>
	    <div class="panel panel-primary">
	        <div class="panel-heading">
	            <h3 class="panel-title">Bugs</h3>
	        </div>
	        <div class="panel-body">
				# contacts.php<br>
				Read - Client: Undefined index: client in /public/contacts.php on line 176.<br>
				<br>
				# employees.php<br>
				After entering data > Create - DB query failed.<br>
				<br>
				#members.php<br>
				When deleting a member - Warning: mysqli_fetch_assoc() expects parameter 1 to be mysqli_result, boolean<br>
				- given on line 46 and 69.<br>
				<br>
				# projects.php<br>
				Error when creating a new record - DB query failed.<br>
				<br>
				# hostvulns.php<br>
				Notice: Undefined index: script_id in hostvulns.php on line 513, 514, and 522<br>
				<br>
				# webvulns.php<br>
				Read - Finding Category: Notice: Undefined index: finding in /public/webvulns.php on line 204<br>
			</div>
		</div>
	</div>
</div>

<?php include '../includes/footer.php'; ?>
