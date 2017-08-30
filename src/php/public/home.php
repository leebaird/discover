<?php
	$bodyid = "home";
	include "../includes/header.php";
	require_once("../includes/common.php");
?>

<div class="row">
	<div class="col-xs-6 col-md-4">
		<br>
		<h4>Welcome <?php echo htmlentities($_SESSION['user']['username'], ENT_QUOTES, 'UTF-8'); ?></h4>
		<br>
		<h4>Settings</h4>
		<ul>
			<li><a href="../includes/edit_account.php">Edit Account</a></li>
			<li><a href="../includes/members.php">Members</a></li>
		</ul>

		<h4>Tools</h4>
		<ul>
    		<li><a href="https://www.acunetix.com/vulnerabilities/web/" target="_blank">acunetix</a></li>
    		<li><a href="https://portswigger.net/KnowledgeBase/Issues/" target="_blank">Burp Suite</a></li>
    		<li><a href="https://www.tenable.com/plugins/index.php?view=all" target="_blank">Nessus</a></li>
    		<li><a href="https://www.rapid7.com/db/search" target="_blank">Nexpose</a></li>
    		<li><a href="https://nmap.org/nsedoc/" target="_blank">nmap scripts</a></li>
		</ul>

		<h4>Additional Links</h4>
		<ul>
    		<li><a href="https://www.exploit-db.com" target="_blank">Exploit Database</a></li>
    		<li><a href="https://www.owasp.org/index.php/Category:OWASP_Top_Ten_Project#tab=OWASP_Top_10_for_2017_Release_Candidate_1" target="_blank">OWASP Top 10</a></li>
    		<li><a href="http://projects.webappsec.org/w/page/13246978/Threat%20Classification" target="_blank">WASC Threat Classification</a></li>
			<li><a href="notes.php">Notes</a></li>
		</ul>
		
		<h4>Dev Work</h4>
		<ul>
			<li><a href="bugs.php">Bugs</a></li>
			<li><a href="todo.php">To Do</a></li>			
		</ul>
	</div>

	<div class="col-xs-12 col-md-8">
		<br><br><br><br><br><br>
    	<div id="datepicker"></div>
		<script> $( "#datepicker" ).datepicker(); </script>
	</div>
</div>

<?php include '../includes/footer.php'; ?>
