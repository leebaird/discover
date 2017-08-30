<?php
$bodyid = "findings";
include "../includes/header.php";
require_once("../includes/common.php");

if (isset($_POST['create'])) {
    // CREATE RECORD.

    // Check for blank fields.
    $type = trim($_POST['type']);
    if (empty($type)) { ?>
        <br>
        <button class="btn btn-danger" type="button"><strong>Warning!</strong> You must enter a type.</button>
        <br><br>
        <a class="btn btn-default" href="findings.php?create" input type="button">Back</a>
        <?php exit;
    }

    $finding = trim($_POST['finding']);
    if (empty($finding)) { ?>
        <br>
        <button class="btn btn-danger" type="button"><strong>Warning!</strong> You must enter a finding.</button>
        <br><br>
        <a class="btn btn-default" href="findings.php?create" input type="button">Back</a>
        <?php exit;
    }

    $finding = mysqli_real_escape_string($connection, $_POST['finding']);
    $observation = mysqli_real_escape_string($connection, $_POST['observation']);
    $severity = mysqli_real_escape_string($connection, $_POST['severity']);
    $remediation = mysqli_real_escape_string($connection, $_POST['remediation']);
    $see_also = mysqli_real_escape_string($connection, $_POST['see_also']);

    $query = "INSERT INTO findings (modified, type, finding, observation, severity, remediation, see_also) VALUES (now(), '".$type."', '".$finding."', '".$observation."', '".$severity."', '".$remediation."', '".$see_also."')";
    $result = mysqli_query($connection, $query);
    confirm_query($result);
}


if (isset($_POST['update'])) {
    // UPDATE RECORD.
    $query = "UPDATE findings SET modified=now(), type='$_POST[type]', finding='$_POST[finding]', observation='$_POST[observation]', severity='$_POST[severity]', remediation='$_POST[remediation]', see_also='$_POST[see_also]' WHERE findingID=".intval($_POST['update']);
  	$result = mysqli_query($connection, $query);
    confirm_query($result);
}


if (isset($_GET['delete'])) {
    // DELETE RECORD.
    $query = "DELETE FROM findings WHERE findingID=".intval($_GET['delete']);
    $result = mysqli_query($connection, $query);
    confirm_query($result);
}


if (isset($_GET['create'])) {
    ?>
    <div class="container">
        <div class="panel panel-primary">
            <div class="panel-heading">
                <h3 class="panel-title">Create Finding</h3>
            </div>
        <div class="panel-body">

        <form class="form-horizontal" action="findings.php" method="post">
            <div class="form-group">
                <label class="col-sm-2 control-label">Type</label>
                <div class="col-sm-10">
                    <select class="form-control" name="type">
                        <option value=""></option>
                        <option value="Host">Host</option>
                        <option value="Mobile">Mobile</option>
                        <option value="Networking">Networking</option>
                        <option value="Physical">Physical</option>
                        <option value="Social Engineering">Social Engineering</option>
                        <option value="Strategic">Strategic</option>
                        <option value="War Dialing">War Dialing</option>
                        <option value="Web">Web</option>
                        <option value="Wireless">Wireless</option>
                    </select>
                </div>
            </div>

            <div class="form-group">
                <label class="col-sm-2 control-label">Finding</label>
                <div class="col-sm-10">
                    <input type="text" class="form-control" name="finding" placeholder="Finding">
                </div>
            </div>

            <div class="form-group">
                <label class="col-sm-2 control-label">Observation</label>
                <div class="col-sm-10">
                    <textarea class="form-control" name="observation" placeholder="Observation" rows="20"></textarea>
                </div>
            </div>

            <div class="form-group">
                <label class="col-sm-2 control-label">Severity</label>
                <div class="col-sm-10">
                    <textarea class="form-control" name="severity" placeholder="Severity" rows="20"></textarea>
                </div>
            </div>

            <div class="form-group">
                <label class="col-sm-2 control-label">Remediation</label>
                <div class="col-sm-10">
                    <textarea class="form-control" name="remediation" placeholder="Remediation" rows="25"></textarea>
                </div>
            </div>

            <div class="form-group">
                <label class="col-sm-2 control-label">See Also</label>
                <div class="col-sm-10">
                    <textarea class="form-control" name="see_also" placeholder="See Also" rows="5"></textarea>
                </div>
            </div>

            <div class="form-actions">
                <button class="btn btn-primary" type="submit" name="create">Create</button>
                <a class="btn btn-default" href="findings.php">Back</a>
            </div>
        </form>
        
        </div>
        </div>
    </div>
    <?php
}


elseif (isset($_GET['read'])) {
    // READ RECORD.
    $query = "SELECT * FROM findings WHERE findingID=".intval($_GET['read']);
    $result = mysqli_query($connection, $query);
    confirm_query($result);
    $row = mysqli_fetch_assoc($result);

	// Find number of records.
	$query2 = "SELECT * FROM findings";
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
                <h3 class="panel-title">Read Finding</h3>
            </div>
            <div class="panel-body">

            <form class="form-horizontal" action="findings.php" method="post">
                <div class="form-group">
                    <label class="col-sm-2 control-label">Type</label>
                    <div class="col-sm-10">
                        <input type="text" class="form-control" name="type" value="<?php echo $row['type'] ?>" readonly>
                    </div>
                </div>

                <div class="form-group">
                    <label class="col-sm-2 control-label">Finding</label>
                    <div class="col-sm-10">
                        <input type="text" class="form-control" name="finding" value="<?php echo $row['finding'] ?>" readonly>
                    </div>
                </div>

                <div class="form-group">
                    <label class="col-sm-2 control-label">Observation</label>
                    <div class="col-sm-10">
                        <textarea class="form-control" name="observation" rows="20" readonly><?php echo $row['observation'] ?></textarea>
                    </div>
                </div>

                <div class="form-group">
                    <label class="col-sm-2 control-label">Severity</label>
                    <div class="col-sm-10">
                        <textarea class="form-control" name="severity" rows="20" readonly><?php echo $row['severity'] ?></textarea>
                    </div>
                </div>

                <div class="form-group">
                    <label class="col-sm-2 control-label">Remediation</label>
                    <div class="col-sm-10">
                        <textarea class="form-control" name="remediation" rows="25" readonly><?php echo $row['remediation'] ?></textarea>
                    </div>
                </div>

                <div class="form-group">
                    <label class="col-sm-2 control-label">See Also</label>
                    <div class="col-sm-10">
                        <textarea class="form-control" name="see_also" rows="5" readonly><?php echo $row['see_also'] ?></textarea>
                    </div>
                </div>

                <div class="form-actions">
                    <a class="btn btn-default" href="findings.php">Back</a>
                </div>
            </form>
            
			</div>
		</div>
	</div>
    <?php
}


elseif (isset($_GET['update'])) {
    // UPDATE RECORD.
    $query = "SELECT * FROM findings WHERE findingID=".intval($_GET['update']);
    $result = mysqli_query($connection, $query);
    confirm_query($result);
    $row = mysqli_fetch_assoc($result);
    ?>

    <div class="container">
        <div class="panel panel-primary">
            <div class="panel-heading">
                <h3 class="panel-title">Update Finding</h3>
            </div>	
            <div class="panel-body">

            <form class="form-horizontal" action="findings.php" method="post">
				<input type = "hidden" name = "update" value = "<?php echo $row['findingID'] ?>">
                <div class="form-group">
                    <label class="col-sm-2 control-label">Type</label>
                    <div class="col-sm-10">
                        <select class="form-control" name="type">
                            <option value=""></option>
                            <option value="Host"<?php echo ($row['type'] == 'Host' ? " selected" : "")?>>Host</option>
                            <option value="Mobile"<?php echo ($row['type'] == 'Mobile' ? " selected" : "")?>>Mobile</option>
                            <option value="Networking"<?php echo ($row['type'] == 'Networking' ? " selected" : "")?>>Networking</option>
                            <option value="Physical"<?php echo ($row['type'] == 'Physical' ? " selected" : "")?>>Physical</option>
                            <option value="Social Engineering"<?php echo ($row['type'] == 'Social Engineering' ? " selected" : "")?>>Social Engineering</option>
                            <option value="Strategic"<?php echo ($row['type'] == 'Strategic' ? " selected" : "")?>>Strategic</option>
                            <option value="War Dialing"<?php echo ($row['type'] == 'War Dialing' ? " selected" : "")?>>War Dialing</option>
                            <option value="Web"<?php echo ($row['type'] == 'Web' ? " selected" : "")?>>Web</option>
                            <option value="Wireless"<?php echo ($row['type'] == 'Wireless' ? " selected" : "")?>>Wireless</option>
                        </select>
                    </div>
                </div>

                <div class="form-group">
                    <label class="col-sm-2 control-label">Finding</label>
                    <div class="col-sm-10">
                        <input type="text" class="form-control" name="finding" value="<?php echo $row['finding'] ?>">
                    </div>
                </div>

                <div class="form-group">
                    <label class="col-sm-2 control-label">Observation</label>
                    <div class="col-sm-10">
                        <textarea class="form-control" name="observation" rows="20"><?php echo $row['observation'] ?></textarea>
                    </div>
                </div>

                <div class="form-group">
                    <label class="col-sm-2 control-label">Severity</label>
                    <div class="col-sm-10">
                        <textarea class="form-control" name="severity" rows="20"><?php echo $row['severity'] ?></textarea>
                    </div>
                </div>

                <div class="form-group">
                    <label class="col-sm-2 control-label">Remediation</label>
                    <div class="col-sm-10">
                        <textarea class="form-control" name="remediation" rows="25"><?php echo $row['remediation'] ?></textarea>
                    </div>
                </div>

                <div class="form-group">
                    <label class="col-sm-2 control-label">See Also</label>
                    <div class="col-sm-10">
                        <textarea class="form-control" name="see_also" rows="5"><?php echo $row['see_also'] ?></textarea>
                    </div>
                </div>

                <div class="form-actions">
                    <button class="btn btn-warning" type="submit">Update</button>
                    <a class="btn btn-default" href="findings.php">Back</a>
                </div>
            </form>
            
			</div>
		</div>
	</div>
    <?php
}


else {
    // DISPLAY LIST OF RECORDS.
    ?>
    <br>
    <a class="btn btn-primary" href="findings.php?create" input type="button">New</a>
    <br>
    <br>

    <?php
        // Perform db query.
        $query = "SELECT * FROM findings ORDER BY type, finding ASC";
        $result = mysqli_query($connection, $query);
        confirm_query($result);
    ?>

    <table style="width: auto;" class="table table-bordered table-condensed table-hover">
        <tr>
            <th style="background-color:#E8E8E8; "</th>
            <th style="background-color:#E8E8E8; "</th>
            <th style="background-color:#E8E8E8; color:#0397B7; text-align:center;">Type</th>
            <th style="background-color:#E8E8E8; color:#0397B7; text-align:center;">Finding Category</th>
            <th style="background-color:#E8E8E8; color:#0397B7; text-align:center;">Modified</th>
            <th style="background-color:#E8E8E8; "></th>
        </tr>

        <?php 
            while($row = mysqli_fetch_assoc($result)) {
				$time = strtotime($row['modified']);
				$myDateFormat = date("m-d-y g:i A", $time);

                echo '
                <tr>
                    <td width="50">'.'<a class="btn btn-primary" href="findings.php?read='.$row['findingID'].'"><span class="glyphicon glyphicon-play"></span></a>'.'</td>
                    <td width="50">'.'<a class="btn btn-warning" href="findings.php?update='.$row['findingID'].'"><span class="glyphicon glyphicon-pencil"></span></a>'.'</td>
                    <td width="150">'.$row["type"].'</td>
                    <td width="425">'.$row["finding"].'</td>
                    <td width="175">'.$myDateFormat.'</td>
                    <td width="50">'.'<a class="btn btn-danger" href="findings.php?delete='.$row['findingID'].'"
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
