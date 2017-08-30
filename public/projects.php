<?php
$bodyid = "projects";
include "../includes/header.php";
require_once("../includes/common.php");

if (isset($_POST['create'])) {
    // CREATE RECORD.

    // Check for blank field.
    $project = trim($_POST['project']);
    if (empty($project)) { ?>
        <br>
        <button class="btn btn-danger" type="button"><strong>Warning!</strong> You must enter a project.</button>
        <br><br>
        <a class="btn btn-default" href="projects.php?create" input type="button">Back</a>
        <?php exit;
    }

    $clientID = trim($_POST['clientID']);
    if (empty($clientID)) { ?>
        <br>
        <button class="btn btn-danger" type="button"><strong>Warning!</strong> You must enter a client.</button>
        <br><br>
        <a class="btn btn-default" href="projects.php?create" input type="button">Back</a>
        <?php exit;
    }

    $query = "INSERT INTO projects (modified, project, current_status, clientID, address, city, state, zip, contact, accountmgr, projectmgr, employee1, employee2, employee3, employee4, assessment, kickoff, start_date, finish, due, notes) VALUES (now(), '$_POST[project]', '$_POST[current_status]', '$_POST[clientID]', '$_POST[address]', '$_POST[city]', '$_POST[state]', '$_POST[zip]', '$_POST[contact]', '$_POST[accountmgr]', '$_POST[projectmgr]', '$_POST[employee1]', '$_POST[employee2]', '$_POST[employee3]', '$_POST[employee4]', '$_POST[assessment]', '$_POST[kickoff]', '$_POST[start_date]', '$_POST[finish]', '$_POST[due]', '$_POST[notes]')";
	$result = mysqli_query($connection, $query);
    confirm_query($result);
}


if (isset($_POST['update'])) {
    // UPDATE RECORD.
    $query = "UPDATE projects SET modified=now(), project='$_POST[project]', , current_status='$_POST[current_status]', clientID='$_POST[clientID]', address='$_POST[address]', city='$_POST[city]', state='$_POST[state]', zip='$_POST[zip]', contact='$_POST[contact]', accountmgr='$_POST[accountmgr]', projectmgr='$_POST[projectmgr]', employee1='$_POST[employee1]', employee2='$_POST[employee2]', employee3='$_POST[employee3]', employee4='$_POST[employee4]', assessment='$_POST[assessment]', kickoff='$_POST[kickoff]', start_date='$_POST[start_date]', finish='$_POST[finish]', due='$_POST[due]', notes='$_POST[notes]' WHERE projectID=".intval($_POST['update']);
  	$result = mysqli_query($connection, $query);
    confirm_query($result);
}


if (isset($_GET['delete'])) {
    // DELETE RECORD.
    $query = "DELETE FROM projects WHERE projectID=".intval($_GET['delete']);
    $result = mysqli_query($connection, $query);
    confirm_query($result);
}


if (isset($_GET['create'])) {
    ?>
    <div class="container">
        <div class="panel panel-primary">
            <div class="panel-heading">
                <h3 class="panel-title">Create Project</h3>
            </div>
        	<div class="panel-body">	
				<ul class="nav nav-tabs" role="tablist">
					<li role="presentation" class="active"><a href="#home" aria-controls="home" role="tab" data-toggle="tab">Home</a></li>
					<li role="presentation"><a href="#report" aria-controls="report" role="tab" data-toggle="tab">Report</a></li>
					<li role="presentation"><a href="#external" aria-controls="external" role="tab" data-toggle="tab">External</a></li>
					<li role="presentation"><a href="#internal" aria-controls="internal" role="tab" data-toggle="tab">Internal</a></li>
					<li role="presentation"><a href="#mobile" aria-controls="mobile" role="tab" data-toggle="tab">Mobile</a></li>
					<li role="presentation"><a href="#physical" aria-controls="physical" role="tab" data-toggle="tab">Physical</a></li>
					<li role="presentation"><a href="#social-eng" aria-controls="social-eng" role="tab" data-toggle="tab">Social Eng</a></li>
					<li role="presentation"><a href="#war-dail" aria-controls="war-dail" role="tab" data-toggle="tab">War Dail</a></li>
					<li role="presentation"><a href="#web" aria-controls="web" role="tab" data-toggle="tab">Web</a></li>
					<li role="presentation"><a href="#wireless" aria-controls="wireless" role="tab" data-toggle="tab">Wireless</a></li>
				</ul>
	            <br>
				<div class="tab-content">
					<!-- External panel -->
					<div role="tabpanel" class="tab-pane active" id="home">
			            <form class="form-horizontal" action="projects.php" method="post">
			                <div class="form-group">
			                    <label class="col-sm-2 control-label">Project</label>
			                    <div class="col-sm-10">
			                        <input type="text" class="form-control" name="project" placeholder="Project">
			                    </div>
			                </div>

			                <div class="form-group">
			                    <label class="col-sm-2 control-label">Status</label>
			                    <div class="col-sm-2">
			                        <select class="form-control" name="current_status">
			                            <option value=""></option>
			                            <option value="Scoping">Scoping</option>
			                            <option value="In Progress">In Progress</option>
			                            <option value="Reporting">Reporting</option>
			                            <option value="Review">Review</option>
			                            <option value="Delivered">Delivered</option>
			                            <option value="Complete">Complete</option>
			                        </select>
			                    </div>
			                </div>

			                <?php
			                    $query = "SELECT * FROM clients ORDER BY client ASC";
			                    $result = mysqli_query($connection, $query);
			                    confirm_query($result);
			                ?>

			                <div class="form-group">
			                    <label class="col-sm-2 control-label">Client</label>
			                    <div class="col-sm-5">
			    					<select class="form-control" name="clientID">
			                            <option value=""></option>
			                            <?php
			                            	while($c = mysqli_fetch_assoc($result)) {
			                            		echo '<option value = "'.$c['clientID'].'">'.$c['client'].'</option>';
			                            	}

			                            	// Release returned data.
			                            	mysqli_free_result($result);
			                            ?>
			    					</select>
			                    </div>
			                </div>

			                <div class="form-group">
			                    <label class="col-sm-2 control-label">Address</label>
			                    <div class="col-sm-5">
			                        <textarea class="form-control" name="address" placeholder="Address" rows="2"></textarea>
			                    </div>
			                </div>

			                <div class="row">
			                    <label class="col-sm-2 control-label">City, State, Zip</label>
			                    <div class="col-sm-2">
			                        <input type="text" class="form-control" name="city" placeholder="City">
			                    </div>

			                    <div class="col-sm-1">
			                        <input type="text" class="form-control" name="state" placeholder="State">
			                    </div>

			                    <div class="col-sm-2">
			                        <input type="text" class="form-control" name="zip" placeholder="Zip">
			                    </div>
			                </div>

			                <br>

			                <div class="form-group">
			                    <label class="col-sm-2 control-label">Contact</label>
			                    <div class="col-sm-3">
			                        <input type="text" class="form-control" name="contact" placeholder="Contact">
			                    </div>
			                </div>

			                <?php
			                    $query = "SELECT * FROM employees WHERE accountmgr='Yes' ORDER BY employee ASC";
			                    $result = mysqli_query($connection, $query);
			                    confirm_query($result);
			                ?>

			                <div class="form-group">
			                    <label class="col-sm-2 control-label">Account Mgr</label>
			                    <div class="col-sm-3">
			    					<select class="form-control" name="employeeID">
			                            <option value=""></option>
			                            <?php
			                            	while($c = mysqli_fetch_assoc($result)) {
			                            		echo '<option value = "'.$c['employeeID'].'">'.$c['employee'].'</option>';
			                            	}

			                            	// Release returned data.
			                            	mysqli_free_result($result);
			                            ?>
			    					</select>
			                    </div>
			                </div>

			                <?php
			                    $query = "SELECT * FROM employees WHERE projectmgr='Yes' ORDER BY employee ASC";
			                    $result = mysqli_query($connection, $query);
			                    confirm_query($result);
			                ?>

			                <div class="form-group">
			                    <label class="col-sm-2 control-label">Project Mgr</label>
			                    <div class="col-sm-3">
			    					<select class="form-control" name="employeeID">
			                            <option value=""></option>
			                            <?php
			                            	while($c = mysqli_fetch_assoc($result)) {
			                            		echo '<option value = "'.$c['employeeID'].'">'.$c['employee'].'</option>';
			                            	}

			                            	// Release returned data.
			                            	mysqli_free_result($result);
			                            ?>
			    					</select>
			                    </div>
			                </div>

			                <div class="form-group">
			                    <label class="col-sm-2 control-label">Employee 1</label>
			                    <div class="col-sm-3">
			                        <input type="text" class="form-control" name="employee1" placeholder="Employee 1">
			                    </div>
			                </div>

			                <div class="form-group">
			                    <label class="col-sm-2 control-label">Employee 2</label>
			                    <div class="col-sm-3">
			                        <input type="text" class="form-control" name="employee2" placeholder="Employee 2">
			                    </div>
			                </div>

			                <div class="form-group">
			                    <label class="col-sm-2 control-label">Employee 3</label>
			                    <div class="col-sm-3">
			                        <input type="text" class="form-control" name="employee3" placeholder="Employee 3">
			                    </div>
			                </div>

			                <div class="form-group">
			                    <label class="col-sm-2 control-label">Employee 4</label>
			                    <div class="col-sm-3">
			                        <input type="text" class="form-control" name="employee4" placeholder="Employee 4">
			                    </div>
			                </div>

			                <div class="form-group">
			                    <label class="col-sm-2 control-label">Assessment</label>
			                    <div class="col-sm-10">
			                        <label class="checkbox-inline">
			                            <input type="checkbox" name="assessment[]" value="External">External
			                        </label>
			                        <label class="checkbox-inline">
			                            <input type="checkbox" name="assessment[]" value="Internal">Internal
			                        </label>
			                        <label class="checkbox-inline">
			                            <input type="checkbox" name="assessment[]" value="Mobile">Mobile
			                        </label>
			                        <label class="checkbox-inline">
			                            <input type="checkbox" name="assessment[]" value="Physical">Physical
			                        </label>
			                        <label class="checkbox-inline">
			                            <input type="checkbox" name="assessment[]" value="Social Eng">Social Eng
			                        </label>
			                        <label class="checkbox-inline">
			                            <input type="checkbox" name="assessment[]" value="War Dialing">War Dialing
			                        </label>
			                        <label class="checkbox-inline">
			                            <input type="checkbox" name="assessment[]" value="Web">Web
			                        </label>
			                        <label class="checkbox-inline">
			                            <input type="checkbox" name="assessment[]" value="Wireless">Wireless
			                        </label>
			                    </div>
			                </div>

			                <div class="form-group">
			                    <label class="col-sm-2 control-label">Kickoff</label>
			                    <div class="col-sm-2">
			                        <input type="text" class="form-control" id="kickoff" name="kickoff" placeholder="Kickoff">
			                        <script> $( "#kickoff" ).datepicker(); </script>
			                    </div>
			                </div>

			                <div class="form-group">
			                    <label class="col-sm-2 control-label">Start</label>
			                    <div class="col-sm-2">
			                        <input type="text" class="form-control" id="start_date" name="start_date" placeholder="Start">
			                        <script> $( "#start_date" ).datepicker(); </script>
			                    </div>
			                </div>

			                <div class="form-group">
			                    <label class="col-sm-2 control-label">Finish</label>
			                    <div class="col-sm-2">
			                        <input type="text" class="form-control" id="finish" name="finish" placeholder="Finish">
			                        <script> $( "#finish" ).datepicker(); </script>
			                    </div>
			                </div>

			               <div class="form-group">
			                    <label class="col-sm-2 control-label">Due</label>
			                    <div class="col-sm-2">
			                        <input type="text" class="form-control" id="due" name="due" placeholder="Due">
			                        <script> $( "#due" ).datepicker(); </script>
			                    </div>
			                </div>

			                <div class="form-group">
			                    <label class="col-sm-2 control-label">Notes</label>
			                    <div class="col-sm-10">
			                        <textarea class="form-control" name="notes" placeholder="Notes" rows="6"></textarea>
			                    </div>
			                </div>

			                <div class="form-actions">
			                    <button class="btn btn-primary" type="submit" name="create">Create</button>
			                    <a class="btn btn-default" href="projects.php">Back</a>
			                </div>
			            </form>
				    </div>

					<!-- Report panel -->
				    <div role="tabpanel" class="tab-pane" id="report">Need to think about this layout.</div>

					<!-- External panel -->
				   	<div role="tabpanel" class="tab-pane" id="external">
			            <form class="form-horizontal" action="projects.php" method="post">						
			                <div class="form-group">
			                    <label class="col-sm-2 control-label">Objective</label>
			                    <div class="col-sm-10">
			                        <textarea class="form-control" name="ext_objective" placeholder="Objective" rows="2"></textarea>
			                    </div>
			                </div>

			                <div class="form-group">
			                    <label class="col-sm-2 control-label">Targets</label>
			                    <div class="col-sm-10">
			                        <input type="text" class="form-control" name="ex_targets" placeholder="Targets">
			                    </div>
			                </div>

			                <div class="form-group">
			                    <label class="col-sm-2 control-label">Exclude</label>
			                    <div class="col-sm-10">
			                        <input type="text" class="form-control" name="ex_exclude" placeholder="Exclude">
			                    </div>
			                </div>

			                <div class="form-group">
			                    <label class="col-sm-2 control-label">Notes</label>
			                    <div class="col-sm-10">
			                        <textarea class="form-control" name="ext_notes" placeholder="Notes" rows="6"></textarea>
			                    </div>
			                </div>
						</form>
				   	</div>

					<!-- Internal panel -->
					<div role="tabpanel" class="tab-pane" id="internal">
			            <form class="form-horizontal" action="projects.php" method="post">						
			                <div class="form-group">
			                    <label class="col-sm-2 control-label">Objective</label>
			                    <div class="col-sm-10">
			                        <textarea class="form-control" name="int_objective" placeholder="Objective" rows="2"></textarea>
			                    </div>
			                </div>

			                <div class="form-group">
			                    <label class="col-sm-2 control-label">Targets</label>
			                    <div class="col-sm-10">
			                        <input type="text" class="form-control" name="int_targets" placeholder="Targets">
			                    </div>
			                </div>

			                <div class="form-group">
			                    <label class="col-sm-2 control-label">Exclude</label>
			                    <div class="col-sm-10">
			                        <input type="text" class="form-control" name="int_exclude" placeholder="Exclude">
			                    </div>
			                </div>

			                <div class="form-group">
			                    <label class="col-sm-2 control-label">Notes</label>
			                    <div class="col-sm-10">
			                        <textarea class="form-control" name="int_notes" placeholder="Notes" rows="6"></textarea>
			                    </div>
			                </div>
						</form>
					</div>

					<!-- Mobile panel -->
					<div role="tabpanel" class="tab-pane" id="mobile">
			            <form class="form-horizontal" action="projects.php" method="post">						
			                <div class="form-group">
			                    <label class="col-sm-2 control-label">Objective</label>
			                    <div class="col-sm-10">
			                        <textarea class="form-control" name="mob_objective" placeholder="Objective" rows="2"></textarea>
			                    </div>
			                </div>

			                <div class="form-group">
			                    <label class="col-sm-2 control-label">Notes</label>
			                    <div class="col-sm-10">
			                        <textarea class="form-control" name="mob_notes" placeholder="Notes" rows="6"></textarea>
			                    </div>
			                </div>
						</form>
					</div>

					<!-- Physical panel -->
					<div role="tabpanel" class="tab-pane" id="physical">
			            <form class="form-horizontal" action="projects.php" method="post">						
			                <div class="form-group">
			                    <label class="col-sm-2 control-label">Objective</label>
			                    <div class="col-sm-10">
			                        <textarea class="form-control" name="phy_objective" placeholder="Objective" rows="2"></textarea>
			                    </div>
							</div>

				            <div class="form-group">
				                <label class="col-sm-2 control-label">Notes</label>
				                <div class="col-sm-10">
				                    <textarea class="form-control" name="phy_notes" placeholder="Notes" rows="6"></textarea>
				                </div>
				            </div>
						</form>
					</div>

					<!-- Social Eng panel -->
					<div role="tabpanel" class="tab-pane" id="social-eng">
			            <form class="form-horizontal" action="projects.php" method="post">						
			                <div class="form-group">
			                    <label class="col-sm-2 control-label">Objective</label>
			                    <div class="col-sm-10">
			                        <textarea class="form-control" name="se_objective" placeholder="Objective" rows="2"></textarea>
			                    </div>
			                </div>

			                <div class="form-group">
			                    <label class="col-sm-2 control-label">Notes</label>
			                    <div class="col-sm-10">
			                        <textarea class="form-control" name="se_notes" placeholder="Notes" rows="6"></textarea>
			                    </div>
			                </div>
						</form>
					</div>

					<!-- War Dail panel -->
					<div role="tabpanel" class="tab-pane" id="war-dail">
			            <form class="form-horizontal" action="projects.php" method="post">						
			                <div class="form-group">
			                    <label class="col-sm-2 control-label">Objective</label>
			                    <div class="col-sm-10">
			                        <textarea class="form-control" name="war_objective" placeholder="Objective" rows="2"></textarea>
			                    </div>
			                </div>

			                <div class="form-group">
			                    <label class="col-sm-2 control-label">Notes</label>
			                    <div class="col-sm-10">
			                        <textarea class="form-control" name="war_notes" placeholder="Notes" rows="6"></textarea>
			                    </div>
			                </div>
						</form>
					</div>

					<!-- Web panel -->
					<div role="tabpanel" class="tab-pane" id="web">
			            <form class="form-horizontal" action="projects.php" method="post">						
			                <div class="form-group">
			                    <label class="col-sm-2 control-label">Objective</label>
			                    <div class="col-sm-10">
			                        <textarea class="form-control" name="web_objective" placeholder="Objective" rows="2"></textarea>
			                    </div>
			                </div>

			                <div class="form-group">
			                    <label class="col-sm-2 control-label">Notes</label>
			                    <div class="col-sm-10">
			                        <textarea class="form-control" name="web_notes" placeholder="Notes" rows="6"></textarea>
			                    </div>
			                </div>
						</form>
					</div>

					<!-- Wireless panel -->
					<div role="tabpanel" class="tab-pane" id="wireless">
			            <form class="form-horizontal" action="projects.php" method="post">						
			                <div class="form-group">
			                    <label class="col-sm-2 control-label">Objective</label>
			                    <div class="col-sm-10">
			                        <textarea class="form-control" name="wire_objective" placeholder="Objective" rows="2"></textarea>
			                    </div>
			                </div>

			                <div class="form-group">
			                    <label class="col-sm-2 control-label">Notes</label>
			                    <div class="col-sm-10">
			                        <textarea class="form-control" name="wire_notes" placeholder="Notes" rows="6"></textarea>
			                    </div>
			                </div>
						</form>
					</div>
				</div>
			</div>
		</div>
	</div>
    <?php
}


elseif (isset($_GET['read'])) {
    // READ RECORD
    $query = "SELECT * FROM projects WHERE projectID=".intval($_GET['read']);
    $result = mysqli_query($connection, $query);
    confirm_query($result);
    $row = mysqli_fetch_assoc($result);

    $query = "SELECT * FROM clients WHERE clientID=".intval($row['clientID']);
    $result = mysqli_query($connection, $query);
    confirm_query($result);
    $c = mysqli_fetch_assoc($result);

	// Find number of records.
	$query2 = "SELECT * FROM projects";
	$result2 = mysqli_query($connection, $query2);
	confirm_query($result2);
	$limit = mysqli_num_rows($result2);

	// Free result set.
	mysqli_free_result($result2);

	// Get the page number or set it to 1 if no page is set.
	$read = isset($_GET['read']) ? (int)$_GET['read'] : 1;
	?>

	<ul class="pager">
	    <?php if ($read > 1): ?>
	        <li class="previous"><a href="?read=<?= ($read - 1)?>">Previous</a></li>
	    <?php endif ?>
	    <?php if ($read < $limit): ?>
	        <li class="previous"><a href="?read=<?= ($read + 1)?>">Next</a></li>
	    <?php endif ?>
	</ul>

    <div class="container">
        <div class="panel panel-primary">
            <div class="panel-heading">
                <h3 class="panel-title">Read Project</h3>
            </div>
            <div class="panel-body">
				<ul class="nav nav-tabs" role="tablist">
					<li role="presentation" class="active"><a href="#home" aria-controls="home" role="tab" data-toggle="tab">Home</a></li>
					<li role="presentation"><a href="#report" aria-controls="report" role="tab" data-toggle="tab">Report</a></li>
					<li role="presentation"><a href="#external" aria-controls="external" role="tab" data-toggle="tab">External</a></li>
					<li role="presentation"><a href="#internal" aria-controls="internal" role="tab" data-toggle="tab">Internal</a></li>
					<li role="presentation"><a href="#mobile" aria-controls="mobile" role="tab" data-toggle="tab">Mobile</a></li>
					<li role="presentation"><a href="#physical" aria-controls="physical" role="tab" data-toggle="tab">Physical</a></li>
					<li role="presentation"><a href="#social-eng" aria-controls="social-eng" role="tab" data-toggle="tab">Social Eng</a></li>
					<li role="presentation"><a href="#war-dail" aria-controls="war-dail" role="tab" data-toggle="tab">War Dail</a></li>
					<li role="presentation"><a href="#web" aria-controls="web" role="tab" data-toggle="tab">Web</a></li>
					<li role="presentation"><a href="#wireless" aria-controls="wireless" role="tab" data-toggle="tab">Wireless</a></li>
				</ul>
	            <br>
				<div class="tab-content">
					<!-- Home panel -->
					<div role="tabpanel" class="tab-pane active" id="home">
	            		<form class="form-horizontal" action="projects.php" method="post">
	                		<div class="form-group">
	                    		<label class="col-sm-2 control-label">Project</label>
	                    		<div class="col-sm-10">
	                        		<input type="text" class="form-control" name="project" value="<?php echo $row['project'] ?>" readonly>
	                    		</div>
	                		</div>

	                		<div class="form-group">
	                    		<label class="col-sm-2 control-label">Status</label>
	                    		<div class="col-sm-2">
	                        		<input type="text" class="form-control" name="current_status" value="<?php echo $row['current_status'] ?>" readonly>
	                    		</div>
	                		</div>

	                		<div class="form-group">
	                    		<label class="col-sm-2 control-label">Client</label>
	                    		<div class="col-sm-5">
	                        		<input type="text" class="form-control" name="clientID" value="<?php echo $c['client'] ?>" readonly>
	                    		</div>
	                		</div>

	                		<div class="form-group">
	                    		<label class="col-sm-2 control-label">Address</label>
	                    		<div class="col-sm-5">
	                        		<textarea class="form-control" name="address" rows="2" readonly><?php echo $row['address'] ?></textarea>
	                    		</div>
	                		</div>

	                		<div class="row">
	                    		<label class="col-sm-2 control-label">City, State, Zip</label>
	                    		<div class="col-sm-2">
	                        		<input type="text" class="form-control" name="city" value="<?php echo $row['city'] ?>" readonly>
	                    		</div>

	                    		<div class="col-sm-1">
	                        		<input type="text" class="form-control" name="state" value="<?php echo $row['state'] ?>" readonly>
	                    		</div>

	                    		<div class="col-sm-2">
	                        		<input type="text" class="form-control" name="zip" value="<?php echo $row['zip'] ?>" readonly>
	                    		</div>
	                		</div>

	                		<br>	

	                		<div class="form-group">
	                    		<label class="col-sm-2 control-label">Contact</label>
	                    		<div class="col-sm-3">
	                        		<input type="text" class="form-control" name="contact" value="<?php echo $row['contact'] ?>" readonly>
	                    		</div>
	                		</div>

	                		<div class="form-group">
	                    		<label class="col-sm-2 control-label">Account Mgr</label>
	                    		<div class="col-sm-3">
	                        		<input type="text" class="form-control" name="accountmgr" value="<?php echo $row['accountmgr'] ?>" readonly>
	                    		</div>
	                		</div>

	                		<div class="form-group">
	                    		<label class="col-sm-2 control-label">Project Mgr</label>
	                    		<div class="col-sm-3">
	                        		<input type="text" class="form-control" name="projectmgr" value="<?php echo $row['projectmgr'] ?>" readonly>
	                    		</div>
	                		</div>

	                		<div class="form-group">
	                    		<label class="col-sm-2 control-label">Employee 1</label>
	                    		<div class="col-sm-3">
	                        		<input type="text" class="form-control" name="employee1" value="<?php echo $row['employee1'] ?>" readonly>
	                    		</div>
	                		</div>

	                		<div class="form-group">
	                    		<label class="col-sm-2 control-label">Employee 2</label>
	                    		<div class="col-sm-3">
	                        		<input type="text" class="form-control" name="employee2" value="<?php echo $row['employee2'] ?>" readonly>
	                    		</div>
	                		</div>

	                		<div class="form-group">
	 						   <label class="col-sm-2 control-label">Employee 3</label>
	                    	   <div class="col-sm-3">
	                        	   <input type="text" class="form-control" name="employee3" value="<?php echo $row['employee3'] ?>" readonly>
	                    	   </div>
	                	   </div>

	                	   <div class="form-group">
	                    	   <label class="col-sm-2 control-label">Employee 4</label>
	                    	   <div class="col-sm-3">
	                        	   <input type="text" class="form-control" name="employee4" value="<?php echo $row['employee4'] ?>" readonly>
	                    	   </div>
	                	   </div>

	                	   <div class="form-group">
	                    	   <label class="col-sm-2 control-label">Assessment</label>
	                    	   <div class="col-sm-10">
	                        	   <label class="checkbox-inline">
	                            	   <input type="checkbox" name="assessment" value="<?php foreach($assessment as $item) echo '$item' ?>">External
	                        	   </label>
	                        	   <label class="checkbox-inline">
	                            	   <input type="checkbox" name="assessment" value="<?php foreach($assessment as $item) echo '$item' ?>">Internal
	                        	   </label>
	                        	   <label class="checkbox-inline">
	                            	   <input type="checkbox" name="assessment" value="<?php foreach($assessment as $item) echo '$item' ?>">Mobile
	                        	   </label>
	                        	   <label class="checkbox-inline">
	                            	   <input type="checkbox" name="assessment" value="<?php foreach($assessment as $item) echo '$item' ?>">Physical
	                        	   </label>
	                        	   <label class="checkbox-inline">
	                            	   <input type="checkbox" name="assessment" value="<?php foreach($assessment as $item) echo '$item' ?>">Social Eng
	                        	   </label>
	                        	   <label class="checkbox-inline">
	                            	   <input type="checkbox" name="assessment" value="<?php foreach($assessment as $item) echo '$item' ?>">War Dialing
	                        	   </label>
	                        	   <label class="checkbox-inline">
	                            	   <input type="checkbox" name="assessment" value="<?php foreach($assessment as $item) echo '$item' ?>">Web
	                        	   </label>
	                        	   <label class="checkbox-inline">
	                            	   <input type="checkbox" name="assessment" value="<?php foreach($assessment as $item) echo '$item' ?>">Wireless
	                        	   </label>
	                    	   </div>
	                	   </div>

	                	   <div class="form-group">
	                    	   <label class="col-sm-2 control-label">Kickoff</label>
	                    	   <div class="col-sm-2">
	                        	   <input type="text" class="form-control" name="kickoff" value="<?php echo $row['kickoff'] ?>" readonly>
	                    	   </div>
	                	   </div>

	                	   <div class="form-group">
	                    	   <label class="col-sm-2 control-label">Start</label>
	                    	   <div class="col-sm-2">
	                        	   <input type="text" class="form-control" name="start_date" value="<?php echo $row['start_date'] ?>" readonly>
	                    	   </div>
	                	   </div>

	                	   <div class="form-group">
	                    	   <label class="col-sm-2 control-label">Finish</label>
	                    	   <div class="col-sm-2">
	                        	   <input type="text" class="form-control" name="finish" value="<?php echo $row['finish'] ?>" readonly>
	                    	   </div>
	                	   </div>

	                	   <div class="form-group">
	                    	   <label class="col-sm-2 control-label">Due</label>
	                    	   <div class="col-sm-2">
	                        	   <input type="text" class="form-control" name="due" value="<?php echo $row['due'] ?>" readonly>
	                    	   </div>
	                	   </div>

	                	   <div class="form-group">
	                    	   <label class="col-sm-2 control-label">Notes</label>
	                    	   <div class="col-sm-10">
	                        	   <textarea class="form-control" name="notes" rows="6" readonly><?php echo $row['notes'] ?></textarea>
	                    	   </div>
	                	   </div>

	                	   <div class="form-actions">
	                    	   <a class="btn btn-default" href="projects.php">Back</a>
	                	   </div>
	            	   </form>
				    </div>

					<!-- Report panel -->
				    <div role="tabpanel" class="tab-pane" id="report">Need to think about this layout.</div>

					<!-- External panel -->
				   	<div role="tabpanel" class="tab-pane" id="external">
	            	    <form class="form-horizontal" action="projects.php" method="post">
		             	    <div class="form-group">
		                 	    <label class="col-sm-2 control-label">Objective</label>
		                 	    <div class="col-sm-10">
		                     	    <textarea class="form-control" name="ext_objective" rows="2" readonly><?php echo $row['ext_objective'] ?></textarea>
		                 	    </div>
		             	    </div>

		            		<div class="form-group">
		                		<label class="col-sm-2 control-label">Targets</label>
		                		<div class="col-sm-10">
		                    		<input type="text" class="form-control" name="ext_targets" value="<?php echo $row['ext_targets'] ?>" readonly>
		                		</div>
		            		</div>

		            		<div class="form-group">
		                		<label class="col-sm-2 control-label">Exclude</label>
		                		<div class="col-sm-10">
		                    		<input type="text" class="form-control" name="ext_exclude" value="<?php echo $row['ext_exclude'] ?>" readonly>
		                		</div>
		            		</div>

		             	    <div class="form-group">
		                 	    <label class="col-sm-2 control-label">Notes</label>
		                 	    <div class="col-sm-10">
		                     	    <textarea class="form-control" name="ext_notes" rows="6" readonly><?php echo $row['ext_notes'] ?></textarea>
		                 	    </div>
		             	    </div>
					    </form>
				   	</div>

					<!-- Internal panel -->
					<div role="tabpanel" class="tab-pane" id="internal">
	            	    <form class="form-horizontal" action="projects.php" method="post">
		              	    <div class="form-group">
		                  	    <label class="col-sm-2 control-label">Objective</label>
		                  	    <div class="col-sm-10">
		                      	    <textarea class="form-control" name="int_objective" rows="2" readonly><?php echo $row['int_objective'] ?></textarea>
		                  	    </div>
		              	    </div>

		            		<div class="form-group">
		                		<label class="col-sm-2 control-label">Targets</label>
		                		<div class="col-sm-10">
		                    		<input type="text" class="form-control" name="int_targets" value="<?php echo $row['int_targets'] ?>" readonly>
		                		</div>
		            		</div>

		            		<div class="form-group">
		                		<label class="col-sm-2 control-label">Exclude</label>
		                		<div class="col-sm-10">
		                    		<input type="text" class="form-control" name="int_exclude" value="<?php echo $row['int_exclude'] ?>" readonly>
		                		</div>
		            		</div>

		              	    <div class="form-group">
		                  	    <label class="col-sm-2 control-label">Notes</label>
		                  	    <div class="col-sm-10">
		                      	    <textarea class="form-control" name="int_notes" rows="6" readonly><?php echo $row['int_notes'] ?></textarea>
		                  	    </div>
		              	    </div>
					    </form>
					</div>

					<!-- Mobile panel -->
					<div role="tabpanel" class="tab-pane" id="mobile">
	            	    <form class="form-horizontal" action="projects.php" method="post">				
		              	    <div class="form-group">
		                  	    <label class="col-sm-2 control-label">Objective</label>
		                  	    <div class="col-sm-10">
		                      	    <textarea class="form-control" name="mob_objective" rows="2" readonly><?php echo $row['mob_objective'] ?></textarea>
		                  	    </div>
		              	    </div>

		              	    <div class="form-group">
		                  	    <label class="col-sm-2 control-label">Notes</label>
		                  	    <div class="col-sm-10">
		                      	    <textarea class="form-control" name="mob_notes" rows="6" readonly><?php echo $row['mob_notes'] ?></textarea>
		                  	    </div>
		              	    </div>
					    </form>
					</div>

					<!-- Physical panel -->
					<div role="tabpanel" class="tab-pane" id="physical">
		            	    <form class="form-horizontal" action="projects.php" method="post">				
		              	    <div class="form-group">
		                  	    <label class="col-sm-2 control-label">Objective</label>
		                  	    <div class="col-sm-10">
		                      	    <textarea class="form-control" name="phy_objective" rows="2" readonly><?php echo $row['phy_objective'] ?></textarea>
		                  	    </div>
		              	    </div>

		              	    <div class="form-group">
		                  	    <label class="col-sm-2 control-label">Notes</label>
		                  	    <div class="col-sm-10">
		                      	    <textarea class="form-control" name="phy_notes" rows="6" readonly><?php echo $row['phy_notes'] ?></textarea>
		                  	    </div>
		              	    </div>
					    </form>
					</div>

					<!-- Social Eng panel -->
					<div role="tabpanel" class="tab-pane" id="social-eng">
	            	    <form class="form-horizontal" action="projects.php" method="post">					
		              	    <div class="form-group">
		                  	    <label class="col-sm-2 control-label">Objective</label>
		                  	    <div class="col-sm-10">
		                      	    <textarea class="form-control" name="se_objective" rows="2" readonly><?php echo $row['se_objective'] ?></textarea>
		                  	    </div>
		              	    </div>

		              	    <div class="form-group">
		                  	    <label class="col-sm-2 control-label">Notes</label>
		                  	    <div class="col-sm-10">
		                      	    <textarea class="form-control" name="se_notes" rows="6" readonly><?php echo $row['se_notes'] ?></textarea>
		                  	    </div>
		              	    </div>
						</form>
					</div>

					<!-- War Dailing panel -->
					<div role="tabpanel" class="tab-pane" id="war-dail">
	            	    <form class="form-horizontal" action="projects.php" method="post">					
		              	    <div class="form-group">
		                  	    <label class="col-sm-2 control-label">Objective</label>
		                  	    <div class="col-sm-10">
		                      	    <textarea class="form-control" name="war_objective" rows="2" readonly><?php echo $row['war_objective'] ?></textarea>
		                  	    </div>
		              	    </div>

		              	    <div class="form-group">
		                  	    <label class="col-sm-2 control-label">Notes</label>
		                  	    <div class="col-sm-10">
		                      	    <textarea class="form-control" name="war_notes" rows="6" readonly><?php echo $row['war_notes'] ?></textarea>
		                  	    </div>
		              	    </div>
						</form>
					</div>

					<!-- Web panel -->
					<div role="tabpanel" class="tab-pane" id="web">
	            	    <form class="form-horizontal" action="projects.php" method="post">					
		              	    <div class="form-group">
		                  	    <label class="col-sm-2 control-label">Objective</label>
		                  	    <div class="col-sm-10">
		                      	    <textarea class="form-control" name="web_objective" rows="2" readonly><?php echo $row['web_objective'] ?></textarea>
		                  	    </div>
		              	    </div>

		              	    <div class="form-group">
		                  	    <label class="col-sm-2 control-label">Notes</label>
		                  	    <div class="col-sm-10">
		                      	    <textarea class="form-control" name="web_notes" rows="6" readonly><?php echo $row['web_notes'] ?></textarea>
		                  	    </div>
		              	    </div>
						</form>
					</div>

					<!-- Wireless panel -->
					<div role="tabpanel" class="tab-pane" id="wireless">
	            	    <form class="form-horizontal" action="projects.php" method="post">					
		              	    <div class="form-group">
		                  	    <label class="col-sm-2 control-label">Objective</label>
		                  	    <div class="col-sm-10">
		                      	    <textarea class="form-control" name="wire_objective" rows="2" readonly><?php echo $row['wire_objective'] ?></textarea>
		                  	    </div>
		              	    </div>

		              	    <div class="form-group">
		                  	    <label class="col-sm-2 control-label">Notes</label>
		                  	    <div class="col-sm-10">
		                      	    <textarea class="form-control" name="wire_notes" rows="6" readonly><?php echo $row['wire_notes'] ?></textarea>
		                  	    </div>
		              	    </div>
						</form>
					</div>
				</div>
			</div>
		</div>
	</div>
    <?php
}


elseif (isset($_GET['update'])) {
    // UPDATE RECORD.
    $query = "SELECT * FROM projects WHERE projectID=".intval($_GET['update']);
    $result = mysqli_query($connection, $query);
    confirm_query($result);
    $row = mysqli_fetch_assoc($result);
    ?>

    <div class="container">
        <div class="panel panel-primary">
            <div class="panel-heading">
                <h3 class="panel-title">Update Project</h3>
            </div>
            <div class="panel-body">
				<ul class="nav nav-tabs" role="tablist">
					<li role="presentation" class="active"><a href="#home" aria-controls="home" role="tab" data-toggle="tab">Home</a></li>
					<li role="presentation"><a href="#report" aria-controls="report" role="tab" data-toggle="tab">Report</a></li>
					<li role="presentation"><a href="#external" aria-controls="external" role="tab" data-toggle="tab">External</a></li>
					<li role="presentation"><a href="#internal" aria-controls="internal" role="tab" data-toggle="tab">Internal</a></li>
					<li role="presentation"><a href="#mobile" aria-controls="mobile" role="tab" data-toggle="tab">Mobile</a></li>
					<li role="presentation"><a href="#physical" aria-controls="physical" role="tab" data-toggle="tab">Physical</a></li>
					<li role="presentation"><a href="#social-eng" aria-controls="social-eng" role="tab" data-toggle="tab">Social Eng</a></li>
					<li role="presentation"><a href="#war-dail" aria-controls="war-dail" role="tab" data-toggle="tab">War Dail</a></li>
					<li role="presentation"><a href="#web" aria-controls="web" role="tab" data-toggle="tab">Web</a></li>
					<li role="presentation"><a href="#wireless" aria-controls="wireless" role="tab" data-toggle="tab">Wireless</a></li>
				</ul>
	            <br>
				<div class="tab-content">
					<!-- Home panel -->
					<div role="tabpanel" class="tab-pane active" id="home">
			            <form class="form-horizontal" action="projects.php" method="post">
							<input type = "hidden" name = "update" value = "<?php echo $row['projectID'] ?>">
			                <div class="form-group">
			                    <label class="col-sm-2 control-label">Project</label>
			                    <div class="col-sm-10">
			                        <input type="text" class="form-control" name="project" value="<?php echo $row['project'] ?>">
			                    </div>
			                </div>

			                <div class="form-group">
			                    <label class="col-sm-2 control-label">Status</label>
			                    <div class="col-sm-2">
			                        <select class="form-control" name="current_status">
			                            <option value=""></option>
			                            <option value="Scoping"<?php echo ($row['current_status'] == 'Scoping' ? " selected" : "")?>>Scoping</option>
			                            <option value="In Progress"<?php echo ($row['current_status'] == 'In Progress' ? " selected" : "")?>>In Progress</option>
			                            <option value="Reporting"<?php echo ($row['current_status'] == 'Reporting' ? " selected" : "")?>>Reporting</option>
			                            <option value="Review"<?php echo ($row['current_status'] == 'Review' ? " selected" : "")?>>Review</option>
			                            <option value="Delivered"<?php echo ($row['current_status'] == 'Delivered' ? " selected" : "")?>>Delivered</option>
			                            <option value="Complete"<?php echo ($row['current_status'] == 'Complete' ? " selected" : "")?>>Complete</option>
			                        </select>
			                    </div>
			                </div>

			                <?php
			                    $query = "SELECT * FROM clients ORDER BY client ASC";
			                    $result = mysqli_query($connection, $query);
			                    confirm_query($result);
			                ?>

			                <div class="form-group">
			                    <label class="col-sm-2 control-label">Client</label>
			                    <div class="col-sm-5">
			    					<select class="form-control" name="clientID">
			                            <option value=""></option>
			                            <?php
			                            	while($c = mysqli_fetch_assoc($result)) {
			                            		echo '<option value = "'.$c["clientID"].'"'.($row['clientID'] == $c['clientID'] ? ' selected' : '').'>'.$c["client"].'</option>';
			                            	}

			                            	// Release returned data.
			                            	mysqli_free_result($result);
			                            ?>
			    					</select>
			                    </div>
			                </div>

			                <div class="form-group">
			                    <label class="col-sm-2 control-label">Address</label>
			                    <div class="col-sm-5">
			                        <textarea class="form-control" name="address" rows="2"><?php echo $row['address'] ?></textarea>
			                    </div>
			                </div>

			                <div class="row">
			                    <label class="col-sm-2 control-label">City, State, Zip</label>
			                    <div class="col-sm-2">
			                        <input type="text" class="form-control" name="city" value="<?php echo $row['city'] ?>">
			                    </div>

			                    <div class="col-sm-1">
			                        <input type="text" class="form-control" name="state" value="<?php echo $row['state'] ?>">
			                    </div>

			                    <div class="col-sm-2">
			                        <input type="text" class="form-control" name="zip" value="<?php echo $row['zip'] ?>">
			                    </div>
			                </div>

			                <br>

			                <div class="form-group">
			                    <label class="col-sm-2 control-label">Contact</label>
			                    <div class="col-sm-3">
			                        <input type="text" class="form-control" name="contact" value="<?php echo $row['contact'] ?>">
			                    </div>
			                </div>

			                <?php
			                    $query = "SELECT * FROM employees WHERE accountmgr='Yes' ORDER BY employee ASC";
			                    $result = mysqli_query($connection, $query);
			                    confirm_query($result);
			                ?>

			                <div class="form-group">
			                    <label class="col-sm-2 control-label">Account Mgr</label>
			                    <div class="col-sm-3">
			    					<select class="form-control" name="employeeID">
			                            <option value=""></option>
			                            <?php
			                            	while($c = mysqli_fetch_assoc($result)) {
			                            		echo '<option value = "'.$c["employeeID"].'"'.($row['employeeID'] == $c['employeeID'] ? ' selected' : '').'>'.$c["employee"].'</option>';
			                            	}

			                            	// Release returned data.
			                            	mysqli_free_result($result);
			                            ?>
			    					</select>
			                    </div>
			                </div>

			                <?php
			                    $query = "SELECT * FROM employees WHERE projectmgr='Yes' ORDER BY employee ASC";
			                    $result = mysqli_query($connection, $query);
			                    confirm_query($result);
			                ?>

			                <div class="form-group">
			                    <label class="col-sm-2 control-label">Project Mgr</label>
			                    <div class="col-sm-3">
			    					<select class="form-control" name="employeeID">
			                            <option value=""></option>
			                            <?php
			                            	while($c = mysqli_fetch_assoc($result)) {
			                            		echo '<option value = "'.$c["employeeID"].'"'.($row['employeeID'] == $c['employeeID'] ? ' selected' : '').'>'.$c["employee"].'</option>';
			                            	}

			                            	// Release returned data.
			                            	mysqli_free_result($result);
			                            ?>
			    					</select>
			                    </div>
			                </div>

			                <div class="form-group">
			                    <label class="col-sm-2 control-label">Employee 1</label>
			                    <div class="col-sm-3">
			                        <input type="text" class="form-control" name="employee1" value="<?php echo $row['employee1'] ?>">
			                    </div>
			                </div>

			                <div class="form-group">
			                    <label class="col-sm-2 control-label">Employee 2</label>
			                    <div class="col-sm-3">
			                        <input type="text" class="form-control" name="employee2" value="<?php echo $row['employee2'] ?>">
			                    </div>
			                </div>

			                <div class="form-group">
			                    <label class="col-sm-2 control-label">Employee 3</label>
			                    <div class="col-sm-3">
			                        <input type="text" class="form-control" name="employee3" value="<?php echo $row['employee3'] ?>">
			                    </div>
			                </div>

			                <div class="form-group">
			                    <label class="col-sm-2 control-label">Employee 4</label>
			                    <div class="col-sm-3">
			                        <input type="text" class="form-control" name="employee4" value="<?php echo $row['employee4'] ?>">
			                    </div>
			                </div>

			                <div class="form-group">
			                    <label class="col-sm-2 control-label">Assessment</label>
			                    <div class="col-sm-10">
			                        <label class="checkbox-inline">
			                            <input type="checkbox" name="assessment[]" value="<?php echo $row['id'] ?>">External
			                        </label>
			                        <label class="checkbox-inline">
			                            <input type="checkbox" name="assessment[]" value="<?php echo $row['id'] ?>">Internal
			                        </label>
			                        <label class="checkbox-inline">
			                            <input type="checkbox" name="assessment[]" value="<?php echo $row['id'] ?>">Mobile
			                        </label>
			                        <label class="checkbox-inline">
			                            <input type="checkbox" name="assessment[]" value="<?php echo $row['id'] ?>">Physical
			                        </label>
			                        <label class="checkbox-inline">
			                            <input type="checkbox" name="assessment[]" value="<?php echo $row['id'] ?>">Social Eng
			                        </label>
			                        <label class="checkbox-inline">
			                            <input type="checkbox" name="assessment[]" value="<?php echo $row['id'] ?>">War Dialing
			                        </label>
			                        <label class="checkbox-inline">
			                            <input type="checkbox" name="assessment[]" value="<?php echo $row['id'] ?>">Web
			                        </label>
			                        <label class="checkbox-inline">
			                            <input type="checkbox" name="assessment[]" value="<?php echo $row['id'] ?>">Wireless
			                        </label>
			                    </div>
			                </div>

			                <div class="form-group">
			                    <label class="col-sm-2 control-label">Kickoff</label>
			                    <div class="col-sm-2">
			                        <input type="text" class="form-control" id="kickoff" name="kickoff" value="<?php echo $row['kickoff'] ?>">
			                        <script> $( "#kickoff" ).datepicker(); </script>
			                    </div>
			                </div>

			                <div class="form-group">
			                    <label class="col-sm-2 control-label">Start</label>
			                    <div class="col-sm-2">
			                        <input type="text" class="form-control" id="start_date" name="start_date" value="<?php echo $row['start_date'] ?>">
			                        <script> $( "#start_date" ).datepicker(); </script>
			                    </div>
			                </div>

			                <div class="form-group">
			                    <label class="col-sm-2 control-label">Finish</label>
			                    <div class="col-sm-2">
			                        <input type="text" class="form-control" id="finish" name="finish" value="<?php echo $row['finish'] ?>">
			                        <script> $( "#finish" ).datepicker(); </script>
			                    </div>
			                </div>

			                <div class="form-group">
			                    <label class="col-sm-2 control-label">Due</label>
			                    <div class="col-sm-2">
			                        <input type="text" class="form-control" id="due" name="due" value="<?php echo $row['due'] ?>">
			                        <script> $( "#due" ).datepicker(); </script>
			                    </div>
			                </div>

			                <div class="form-group">
			                    <label class="col-sm-2 control-label">Notes</label>
			                    <div class="col-sm-10">
			                        <textarea class="form-control" name="notes" rows="6"><?php echo $row['notes'] ?></textarea>
			                    </div>
			                </div>

			                <div class="form-actions">
			                    <button class="btn btn-warning" type="submit">Update</button>
			                    <a class="btn btn-default" href="projects.php">Back</a>
			                </div>
			            </form>
					</div>

					<!-- Report panel -->
				    <div role="tabpanel" class="tab-pane" id="report">Need to think about this layout.</div>

					<!-- External panel -->
				   	<div role="tabpanel" class="tab-pane" id="external">
	            	    <form class="form-horizontal" action="projects.php" method="post">						
			                <div class="form-group">
			                    <label class="col-sm-2 control-label">Objective</label>
			                    <div class="col-sm-10">
			                        <textarea class="form-control" name="ext_objective" rows="2"><?php echo $row['ext_objective'] ?></textarea>
			                    </div>
			                </div>

			                <div class="form-group">
			                    <label class="col-sm-2 control-label">Targets</label>
			                    <div class="col-sm-10">
			                        <input type="text" class="form-control" name="ext_targets" value="<?php echo $row['ext_targets'] ?>">
			                    </div>
			                </div>

			                <div class="form-group">
			                    <label class="col-sm-2 control-label">Exclude</label>
			                    <div class="col-sm-10">
			                        <input type="text" class="form-control" name="ext_exclude" value="<?php echo $row['ext_exclude'] ?>">
			                    </div>
			                </div>

			                <div class="form-group">
			                    <label class="col-sm-2 control-label">Notes</label>
			                    <div class="col-sm-10">
			                        <textarea class="form-control" name="ext_notes" rows="6"><?php echo $row['ext_notes'] ?></textarea>
			                    </div>
			                </div>
						</form>
				   	</div>

					<!-- Internal panel -->
					<div role="tabpanel" class="tab-pane" id="internal">
	            	    <form class="form-horizontal" action="projects.php" method="post">						
			                <div class="form-group">
			                    <label class="col-sm-2 control-label">Objective</label>
			                    <div class="col-sm-10">
			                        <textarea class="form-control" name="int_objective" rows="2"><?php echo $row['int_objective'] ?></textarea>
			                    </div>
			                </div>

			                <div class="form-group">
			                    <label class="col-sm-2 control-label">Targets</label>
			                    <div class="col-sm-10">
			                        <input type="text" class="form-control" name="int_targets" value="<?php echo $row['int_targets'] ?>">
			                    </div>
			                </div>

			                <div class="form-group">
			                    <label class="col-sm-2 control-label">Exclude</label>
			                    <div class="col-sm-10">
			                        <input type="text" class="form-control" name="int_exclude" value="<?php echo $row['int_exclude'] ?>">
			                    </div>
			                </div>

			                <div class="form-group">
			                    <label class="col-sm-2 control-label">Notes</label>
			                    <div class="col-sm-10">
			                        <textarea class="form-control" name="int_notes" rows="6"><?php echo $row['int_notes'] ?></textarea>
			                    </div>
			                </div>
						</form>
					</div>

					<!-- Mobile panel -->
					<div role="tabpanel" class="tab-pane" id="mobile">
	            	    <form class="form-horizontal" action="projects.php" method="post">						
			                <div class="form-group">
			                    <label class="col-sm-2 control-label">Objective</label>
			                    <div class="col-sm-10">
			                        <textarea class="form-control" name="mob_objective" rows="2"><?php echo $row['mob_objective'] ?></textarea>
			                    </div>
			                </div>

			                <div class="form-group">
			                    <label class="col-sm-2 control-label">Notes</label>
			                    <div class="col-sm-10">
			                        <textarea class="form-control" name="mob_notes" rows="6"><?php echo $row['mob_notes'] ?></textarea>
			                    </div>
			                </div>
						</form>
					</div>

					<!-- Physical panel -->
					<div role="tabpanel" class="tab-pane" id="physical">
	            	    <form class="form-horizontal" action="projects.php" method="post">						
			                <div class="form-group">
			                    <label class="col-sm-2 control-label">Objective</label>
			                    <div class="col-sm-10">
			                        <textarea class="form-control" name="phy_objective" rows="2"><?php echo $row['phy_objective'] ?></textarea>
			                    </div>
			                </div>

			                <div class="form-group">
			                    <label class="col-sm-2 control-label">Notes</label>
			                    <div class="col-sm-10">
			                        <textarea class="form-control" name="phy_notes" rows="6"><?php echo $row['phy_notes'] ?></textarea>
			                    </div>
			                </div>
						</form>
					</div>

					<!-- Social Eng panel -->
					<div role="tabpanel" class="tab-pane" id="social-eng">
	            	    <form class="form-horizontal" action="projects.php" method="post">						
			                <div class="form-group">
			                    <label class="col-sm-2 control-label">Objective</label>
			                    <div class="col-sm-10">
			                        <textarea class="form-control" name="se_objective" rows="2"><?php echo $row['se_objective'] ?></textarea>
			                    </div>
			                </div>

			                <div class="form-group">
			                    <label class="col-sm-2 control-label">Notes</label>
			                    <div class="col-sm-10">
			                        <textarea class="form-control" name="se_notes" rows="6"><?php echo $row['se_notes'] ?></textarea>
			                    </div>
			                </div>
						</form>
					</div>

					<!-- War Dail panel -->
					<div role="tabpanel" class="tab-pane" id="war-dail">
	            	    <form class="form-horizontal" action="projects.php" method="post">						
			                <div class="form-group">
			                    <label class="col-sm-2 control-label">Objective</label>
			                    <div class="col-sm-10">
			                        <textarea class="form-control" name="war_objective" rows="2"><?php echo $row['war_objective'] ?></textarea>
			                    </div>
			                </div>

			                <div class="form-group">
			                    <label class="col-sm-2 control-label">Notes</label>
			                    <div class="col-sm-10">
			                        <textarea class="form-control" name="war_notes" rows="6"><?php echo $row['war_notes'] ?></textarea>
			                    </div>
			                </div>
						</form>
					</div>

					<!-- Web panel -->
					<div role="tabpanel" class="tab-pane" id="web">
	            	    <form class="form-horizontal" action="projects.php" method="post">						
			                <div class="form-group">
			                    <label class="col-sm-2 control-label">Objective</label>
			                    <div class="col-sm-10">
			                        <textarea class="form-control" name="web_objective" rows="2"><?php echo $row['web_objective'] ?></textarea>
			                    </div>
			                </div>

			                <div class="form-group">
			                    <label class="col-sm-2 control-label">Notes</label>
			                    <div class="col-sm-10">
			                        <textarea class="form-control" name="web_notes" rows="6"><?php echo $row['web_notes'] ?></textarea>
			                    </div>
			                </div>
						</form>
					</div>

					<!-- Wireless panel -->
					<div role="tabpanel" class="tab-pane" id="wireless">
	            	    <form class="form-horizontal" action="projects.php" method="post">						
			                <div class="form-group">
			                    <label class="col-sm-2 control-label">Objective</label>
			                    <div class="col-sm-10">
			                        <textarea class="form-control" name="wire_objective" rows="2"><?php echo $row['wire_objective'] ?></textarea>
			                    </div>
			                </div>

			                <div class="form-group">
			                    <label class="col-sm-2 control-label">Notes</label>
			                    <div class="col-sm-10">
			                        <textarea class="form-control" name="wire_notes" rows="6"><?php echo $row['wire_notes'] ?></textarea>
			                    </div>
			                </div>
						</form>
					</div>
				</div>
			</div>
		</div>
    </div>
	<?php
}


else {
    // DISPLAY LIST OF RECORDS.
    ?>
    <br>
    <a class="btn btn-primary" href="projects.php?create" input type="button">New</a>
    <br>
    <br>

    <?php
        // Perform db query.
        $query = "SELECT * FROM projects ORDER BY project ASC";
        $result = mysqli_query($connection, $query);
        confirm_query($result);
    ?>

    <table style="width: auto;" class="table table-bordered table-condensed table-hover">
        <tr>
            <th style="background-color:#E8E8E8;"></th>
            <th style="background-color:#E8E8E8;"></th>
            <th style="background-color:#E8E8E8; color:#0397B7; font-weight:bold; text-align:center;">Project</th>
            <th style="background-color:#E8E8E8; color:#0397B7; font-weight:bold; text-align:center;">Client</th>
            <th style="background-color:#E8E8E8; color:#0397B7; font-weight:bold; text-align:center;">Kickoff</th>
            <th style="background-color:#E8E8E8; color:#0397B7; font-weight:bold; text-align:center;">Start</th>
            <th style="background-color:#E8E8E8; color:#0397B7; font-weight:bold; text-align:center;">Status</th>
            <th style="background-color:#E8E8E8; color:#0397B7; text-align:center;">Modified</th>
            <th style="background-color:#E8E8E8;"></th>
        </tr>

        <?php
            while($row = mysqli_fetch_assoc($result)) {
                $time = strtotime($row['modified']);
                $myDateFormat = date("m-d-y g:i A", $time);
				$query = "SELECT * FROM clients where clientID = ".intval($row['clientID']);
				$client = mysqli_query($connection, $query);
				confirm_query($client);
				$client = mysqli_fetch_assoc($client);

                echo '
                <tr>
                    <td width="50">'.'<a class="btn btn-primary" href="projects.php?read='.$row['projectID'].'"><span class="glyphicon glyphicon-play"></span></a>'.'</td>
                    <td width="50">'.'<a class="btn btn-warning" href="projects.php?update='.$row['projectID'].'"><span class="glyphicon glyphicon-pencil"></span></a>'.'</td>
                    <td width="300">'.$row["project"].'</td>
                    <td width="300">'.$client['client'].'</td>
                    <td width="125">'.$row["kickoff"].'</td>
                    <td width="125">'.$row["start_date"].'</td>
                    <td width="125">'.$row["current_status"].'</td>
                    <td width="175">'.$myDateFormat.'</td>
                    <td width="50">'.'<a class="btn btn-danger" href="projects.php?delete='.$row['projectID'].'"
                        onclick="return confirm(\'Are you sure you want to delete this record?\');"><span class="glyphicon glyphicon-trash"></span></a>'.'</td>
                </tr>';
            }

            // Release returned data.
            mysqli_free_result($result);
        ?>
    </table>
    <?php
}
?>

<?php include '../includes/footer.php'; ?>
