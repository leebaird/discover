<?php
$bodyid = "webvulns";
include "../includes/header.php";
require_once("../includes/common.php");

if (isset($_POST['create'])) {
    // CREATE RECORD.

    // Check for blank fields.
    $tool = trim($_POST['tool']);
    if (empty($tool)) { ?>
        <br>
        <button class="btn btn-danger" type="button"><strong>Warning!</strong> You must enter a tool.</button>
        <br><br>
        <a class="btn btn-default" href="webvulns.php?create" input type="button">Back</a>
        <?php exit;
    }

    $vulnerability = trim($_POST['vulnerability']);
    if (empty($vulnerability)) { ?>
        <br>
        <button class="btn btn-danger" type="button"><strong>Warning!</strong> You must enter a vulnerability.</button>
        <br><br>
        <a class="btn btn-default" href="webvulns.php?create" input type="button">Back</a>
        <?php exit;
    }

    $query = "INSERT INTO webvulns (modified, tool, vulnerability, findingID, severity, description, remediation, see_also) VALUES ( now(), '".addslashes($_POST['tool'])."', '".addslashes($_POST['vulnerability'])."', '".addslashes($_POST['findingID'])."', '".addslashes($_POST['severity'])."', '".addslashes($_POST['description'])."', '".addslashes($_POST['remediation'])."', '".addslashes($_POST['see_also'])."')";
    $result = mysqli_query($connection, $query);
    confirm_query($result);
}


if (isset($_POST['update'])) {
    // UPDATE RECORD.
    $query = "UPDATE webvulns SET tool='".addslashes($_POST['tool'])."', vulnerability='".addslashes($_POST['vulnerability'])."', findingID='".addslashes($_POST['findingID'])."', severity='".addslashes($_POST['severity'])."', modified=now(), description='".addslashes($_POST['description'])."', remediation='".addslashes($_POST['remediation'])."', see_also='".addslashes($_POST['see_also'])."' WHERE webvulnID=".intval($_POST['update']);
  	$result = mysqli_query($connection, $query);
    confirm_query($result);
}


if (isset($_GET['delete'])) {
    // DELETE RECORD.
    $query = "DELETE FROM webvulns WHERE webvulnID=".intval($_GET['delete']);
    $result = mysqli_query($connection, $query);
    confirm_query($result);
}


if (isset($_GET['create'])) {
    ?>
    <div class="container">
        <div class="panel panel-primary">
            <div class="panel-heading">
                <h3 class="panel-title">Create Web Vulnerability</h3>
            </div>

        <div class="panel-body">
            <form class="form-horizontal" action="webvulns.php" method="post">
                <div class="form-group">
                    <label class="col-sm-2 control-label">Tool</label>
                    <div class="col-sm-2">
                        <select class="form-control" name="tool">
                            <option value=""></option>
                            <option value="acunetix">acunetix</option>
                            <option value="Burp">Burp</option>
                            <option value="WebInspect">WebInspect</option>
                        </select>
                    </div>
                </div>

                <div class="form-group">
                    <label class="col-sm-2 control-label">Vulnerability</label>
                    <div class="col-sm-10">
                        <input type="text" class="form-control" name="vulnerability" placeholder="Vulnerability">
                    </div>
                </div>

                <?php
                    $query = "SELECT * FROM findings WHERE type='Web App' ORDER BY finding ASC";
                    $result = mysqli_query($connection, $query);
                    confirm_query($result);
                ?>

                <div class="form-group">
                    <label class="col-sm-2 control-label">Finding Category</label>
                    <div class="col-sm-5">
                        <select class="form-control" name="findingID">
                            <option value=""></option>
                            <?php
                                while($c = mysqli_fetch_assoc($result)) {
                                    echo '<option value = "'.$c['findingID'].'">'.$c['finding'].'</option>';
                                }

                                // Release returned data.
                                mysqli_free_result($result);
                            ?>
                        </select>
                    </div>
                </div>

                <div class="form-group">
                    <label class="col-sm-2 control-label">Severity</label>
                    <div class="col-sm-2">
                        <select class="form-control" name="severity">
                            <option value=""></option>
                            <option value="Critical">Critical</option>
                            <option value="High">High</option>
                            <option value="Medium">Medium</option>
                            <option value="Low">Low</option>
                            <option value="Info">Info</option>
                        </select>
                    </div>
                </div>

                <div class="form-group">
                    <label class="col-sm-2 control-label">Description</label>
                    <div class="col-sm-10">
                        <textarea class="form-control" name="description" placeholder="Description" rows="25"></textarea>
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
                    <a class="btn btn-default" href="webvulns.php">Back</a>
                </div>
            </form>
        
        </div>
        </div>
    </div>
    <?php
}


elseif (isset($_GET['read'])) {
    // READ RECORD
    $query = "SELECT * FROM webvulns WHERE webvulnID=".intval($_GET['read']);
    $result = mysqli_query($connection, $query);
    confirm_query($result);
    $row = mysqli_fetch_assoc($result);

	// Find number of records.
	$query2 = "SELECT * FROM webvulns";
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
                <h3 class="panel-title">Read Web Vulnerability</h3>
            </div>
            <div class="panel-body">
    
            <form class="form-horizontal" action="webvulns.php" method="post">
                <div class="form-group">
                    <label class="col-sm-2 control-label">Tool</label>
                    <div class="col-sm-2">
                        <input type="text" class="form-control" name="tool" value="<?php echo $row['tool'] ?>" readonly>
                    </div>
                </div>

                <div class="form-group">
                    <label class="col-sm-2 control-label">Vulnerability</label>
                    <div class="col-sm-10">
                        <input type="text" class="form-control" name="vulnerability" value="<?php echo $row['vulnerability'] ?>" readonly>
                    </div>
                </div>

                <div class="form-group">
                    <label class="col-sm-2 control-label">Finding Category</label>
                    <div class="col-sm-5">
                        <input type="text" class="form-control" name="findingID" value="<?php echo $row['finding'] ?>" readonly>
                    </div>
                </div>

                <div class="form-group">
                    <label class="col-sm-2 control-label">Severity</label>
                    <div class="col-sm-2">
                        <input type="text" class="form-control" name="severity" value="<?php echo $row['severity'] ?>" readonly>
                    </div>
                </div>

                <div class="form-group">
                    <label class="col-sm-2 control-label">Description</label>
                    <div class="col-sm-10">
                        <textarea class="form-control" name="description" rows="25" readonly><?php echo $row['description'] ?></textarea>
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
                    <a class="btn btn-default" href="webvulns.php">Back</a>
                </div>
            </form>
            
			</div>
		</div>
	</div>
    <?php
}


elseif (isset($_GET['update'])) {
    // UPDATE RECORD
    $query = "SELECT * FROM webvulns WHERE webvulnID=".intval($_GET['update']);
    $result = mysqli_query($connection, $query);
    confirm_query($result);
    $row = mysqli_fetch_assoc($result);
    ?>

    <div class="container">
        <div class="panel panel-primary">
            <div class="panel-heading">
                <h3 class="panel-title">Update Web Vulnerability</h3>
            </div>	
            <div class="panel-body">

            <form class="form-horizontal" action="webvulns.php" method="post">
				<input type = "hidden" name = "update" value = "<?php echo $row['webvulnID'] ?>">
                <div class="form-group">
                    <label class="col-sm-2 control-label">Tool</label>
                    <div class="col-sm-2">
                        <select class="form-control" name="tool">
                            <option value=""></option>
                            <option value="acunetix"<?php echo ($row['tool'] == 'acunetix' ? " selected" : "")?>>acunetix</option>
                            <option value="Burp"<?php echo ($row['tool'] == 'Burp' ? " selected" : "")?>>Burp</option>
                            <option value="WebInspect"<?php echo ($row['tool'] == 'WebInspect' ? " selected" : "")?>>WebInspect</option>
                        </select>
                    </div>
                </div>

                <div class="form-group">
                    <label class="col-sm-2 control-label">Vulnerability</label>
                    <div class="col-sm-10">
                        <input type="text" class="form-control" name="vulnerability" value="<?php echo $row['vulnerability'] ?>">
                    </div>
                </div>

                <?php
                    $query = "SELECT * FROM findings WHERE type='Web' ORDER BY finding ASC";
                    $result = mysqli_query($connection, $query);
                    confirm_query($result);
                ?>

                <div class="form-group">
                    <label class="col-sm-2 control-label">Finding Category</label>
                    <div class="col-sm-5">
                        <select class="form-control" name="findingID">
                            <option value=""></option>
                            <?php
                            	while($c = mysqli_fetch_assoc($result)) {
                            		echo '<option value = "'.$c["findingID"].'"'.($row['findingID'] == $c['findingID'] ? ' selected' : '').'>'.$c["finding"].'</option>';
                            	}

                            	// Release returned data.
                            	mysqli_free_result($result);
                            ?>
                        </select>
                    </div>
                </div>

                <div class="form-group">
                    <label class="col-sm-2 control-label">Severity</label>
                    <div class="col-sm-2">
                        <select class="form-control" name="severity">
                            <option value=""></option>
                            <option value="Critical"<?php echo ($row['severity'] == 'Critical' ? " selected" : "")?>>Critical</option>
                            <option value="High"<?php echo ($row['severity'] == 'High' ? " selected" : "")?>>High</option>
                            <option value="Medium"<?php echo ($row['severity'] == 'Medium' ? " selected" : "")?>>Medium</option>
                            <option value="Low"<?php echo ($row['severity'] == 'Low' ? " selected" : "")?>>Low</option>
                            <option value="Info"<?php echo ($row['severity'] == 'Info' ? " selected" : "")?>>Info</option>
                        </select>
                    </div>
                </div>

                <div class="form-group">
                    <label class="col-sm-2 control-label">Description</label>
                    <div class="col-sm-10">
                        <textarea class="form-control" name="description" rows="25"><?php echo $row['description'] ?></textarea>
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
                    <a class="btn btn-default" href="webvulns.php">Back</a>
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
    <a class="btn btn-primary" href="webvulns.php?create" input type="button">New</a>
    <br>
    <br>

    <?php
		// Number of rows per page.
		$rec_limit = 25;

		if (isset($_SESSION['rec_limit']))
			$rec_limit = $_SESSION['rec_limit'];

		// Get the total number of records.
		$query = "SELECT COUNT(vulnerability) FROM webvulns";    
		$result = mysqli_query($connection, $query);
		confirm_query($result);

		$row = mysqli_fetch_array ($result, MYSQLI_NUM);
		$rec_count = $row[0];
		$page = 0;
		$offset = 0;

		if (isset($_GET['page'])) {
    		$page = $_GET['page'];
    		$offset = $rec_limit * $page ;
		}

		$left_rec = $rec_count - ($page * $rec_limit);

        // Perform db query.
        $query = "SELECT * FROM webvulns ORDER BY tool, vulnerability ASC LIMIT $offset, $rec_limit";
        $hostset = mysqli_query($connection, $query);
        confirm_query($result);
    ?>

    <table style="width: auto;" class="table table-bordered table-condensed table-hover">
        <tr>
            <th style="background-color:#E8E8E8; "</th>
            <th style="background-color:#E8E8E8; "</th>
            <th style="background-color:#E8E8E8; color:#0397B7; text-align:center;">Tool</th>
            <th style="background-color:#E8E8E8; color:#0397B7; text-align:center;">Web Vulnerability</th>
            <th style="background-color:#E8E8E8; color:#0397B7; text-align:center;">Finding Category</th>
            <th style="background-color:#E8E8E8; color:#0397B7; text-align:center;">Severity</th>
            <th style="background-color:#E8E8E8; color:#0397B7; text-align:center;">Modified</th>
            <th style="background-color:#E8E8E8; "></th>
        </tr>

        <?php
            while($row = mysqli_fetch_assoc($hostset)) {
				$time = strtotime($row['modified']);
				$myDateFormat = date("m-d-y g:i A", $time);
				$query = "SELECT * FROM findings where findingID = ".intval($row['findingID']);
				$finding = mysqli_query($connection, $query);
				confirm_query($finding);
				$finding = mysqli_fetch_assoc($finding);

                echo '
                <tr>
                    <td width="50">'.'<a class="btn btn-primary" href="webvulns.php?read='.$row['webvulnID'].'"><span class="glyphicon glyphicon-play"></span></a>'.'</td>
                    <td width="50">'.'<a class="btn btn-warning" href="webvulns.php?update='.$row['webvulnID'].'"><span class="glyphicon glyphicon-pencil"></span></a>'.'</td>
                    <td width="100">'.$row["tool"].'</td>
                    <td width="500">'.$row["vulnerability"].'</td>
                    <td width="425">'.$finding['finding'].'</td>
                    <td width="100">'.$row["severity"].'</td>
                    <td width="175">'.$myDateFormat.'</td>
                    <td width="50">'.'<a class="btn btn-danger" href="webvulns.php?delete='.$row['webvulnID'].'"
                        onclick="return confirm(\'Are you sure you want to delete this record?\');"><span class="glyphicon glyphicon-trash"></span></a>'.'</td>
                </tr>';
            }

            // Release returned data.
            mysqli_free_result($result);
        ?>
    </table>

	<form method="post" action="">
        <?php
    		if ( $left_rec < $rec_limit && $page > 0 ) {
    			$last = $page - 1;
    			echo '<a href="?page='.$last.'">Previous</a>';
    		}

    		elseif ( $page == 0 && $rec_limit < $rec_count ) {
    			$page = 1;
    			echo '<a href="?page='.$page.'">Next</a>';
    		}

    		elseif ( $page > 0 ) {
    			$last = $page - 1;
    			$page = $page + 1;
    			echo '<a href="?page='.$last.'">Previous</a> | ';
    			echo '<a href="?page='.$page.'">Next</a>';
    		}

    		echo '
    		<select name="set_rec_limit" onchange="this.form.submit()">
    			<option value="25"'.($rec_limit == 25 ? ' selected' : '').'>25</option>
    			<option value="50"'.($rec_limit == 50 ? ' selected' : '').'>50</option>
    			<option value="100"'.($rec_limit == 100 ? ' selected' : '').'>100</option>
    			<option value="200"'.($rec_limit == 200 ? ' selected' : '').'>200</option>
    		</select>
    		';
    	?>
    </form>

    <?php
}

include '../includes/footer.php'; ?>
