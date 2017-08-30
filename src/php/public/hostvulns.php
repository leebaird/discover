<?php
$bodyid = "hostvulns";
include "../includes/header.php";
require_once("../includes/common.php");

if (isset($_POST['set_rec_limit']))
	$_SESSION['rec_limit'] = $_POST['set_rec_limit'];

if (isset($_POST['create'])) {
    // CREATE RECORD.

    // Check for blank fields.
    $tool = trim($_POST['tool']);
    if (empty($tool)) { ?>
        <br>
        <button class="btn btn-danger" type="button"><strong>Warning!</strong> You must enter a tool.</button>
        <br><br>
        <a class="btn btn-default" href="hostvulns.php?create" input type="button">Back</a>
        <?php exit;
    }

    $vulnerability = trim($_POST['vulnerability']);
    if (empty($vulnerability)) { ?>
        <br>
        <button class="btn btn-danger" type="button"><strong>Warning!</strong> You must enter a vulnerability.</button>
        <br><br>
        <a class="btn btn-default" href="hostvulns.php?create" input type="button">Back</a>
        <?php exit;
    }

    $query = "INSERT INTO hostvulns (modified, tool, vulnerability, findingID, cvss_base, internal, external, description, remediation, see_also, published, updated) VALUES (now(), '".addslashes($_POST['tool'])."', '".addslashes($_POST['vulnerability'])."', '".addslashes($_POST['findingID'])."', '".addslashes($_POST['cvss_base'])."', '".addslashes($_POST['internal'])."', '".addslashes($_POST['external'])."', '".addslashes($_POST['description'])."', '".addslashes($_POST['remediation'])."', '".addslashes($_POST['see_also'])."', '".addslashes($_POST['published'])."', '".addslashes($_POST['updated'])."')";
    $result = mysqli_query($connection, $query);
    confirm_query($result);
}


if (isset($_POST['update'])) {
    // UPDATE RECORD.
    $query = "UPDATE hostvulns SET modified=now(), tool='".addslashes($_POST['tool'])."', vulnerability='".addslashes($_POST['vulnerability'])."', findingID='".addslashes($_POST['findingID'])."', cvss_base='".addslashes($_POST['cvss_base'])."', internal='".addslashes($_POST['internal'])."', external='".addslashes($_POST['external'])."', description='".addslashes($_POST['description'])."', remediation='".addslashes($_POST['remediation'])."', see_also='".addslashes($_POST['see_also'])."', published='".addslashes($_POST['published'])."', updated='".addslashes($_POST['updated'])."' WHERE script_id=".intval($_POST['update']);
  	$result = mysqli_query($connection, $query);
    confirm_query($result);
}


if (isset($_GET['delete'])) {
    // DELETE RECORD.
    $query = "DELETE FROM hostvulns WHERE script_id=".intval($_GET['delete']);
    $result = mysqli_query($connection, $query);
    confirm_query($result);
}


if (isset($_GET['create'])) {
    ?>
    <div class="container">
        <div class="panel panel-primary">
            <div class="panel-heading">
                <h3 class="panel-title">Create Host Vulnerability</h3>
            </div>

        <div class="panel-body">
            <form class="form-horizontal" action="hostvulns.php" method="post">
                <div class="form-group">
                    <label class="col-sm-2 control-label">Tool</label>
                    <div class="col-sm-2">
                        <select class="form-control" name="tool">
                            <option value=""></option>
                            <option value="Nessus">Nessus</option>
                            <option value="Nexpose">Nexpose</option>
                            <option value="Qualys">Qualys</option>
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
                    $query = "SELECT * FROM findings WHERE type='Host' ORDER BY finding ASC";
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
                    <label class="col-sm-2 control-label">CVSS Base Score</label>
                    <div class="col-sm-2">
                        <input type="text" class="form-control" name="cvss_base" placeholder="CVSS Base Score">
                    </div>
                </div>

                <div class="row">
                    <label class="col-sm-2 control-label">Internal</label>
                    <div class="col-sm-2">
                        <select class="form-control" name="internal">
                            <option value=""></option>
                            <option value="Critical">Critical</option>
                            <option value="High">High</option>
                            <option value="Medium">Medium</option>
                            <option value="Low">Low</option>
                            <option value="Info">Info</option>
                        </select>
                    </div>

                    <label class="col-sm-1 control-label">External</label>
                    <div class="col-sm-2">
                        <select class="form-control" name="external">
                            <option value=""></option>
                            <option value="Critical">Critical</option>
                            <option value="High">High</option>
                            <option value="Medium">Medium</option>
                            <option value="Low">Low</option>
                            <option value="Info">Info</option>
                        </select>
                    </div>
                </div>
                <br>

                <div class="row">
                    <label class="col-sm-2 control-label">Published</label>
                    <div class="col-sm-2">
                        <input type="text" class="form-control" name="published" placeholder="Published">
                    </div>

                    <label class="col-sm-1 control-label">Updated</label>
                    <div class="col-sm-2">
                        <input type="text" class="form-control" name="updated" placeholder="Updated">
                    </div>
                </div>
                <br>

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
                    <a class="btn btn-default" href="hostvulns.php">Back</a>
                </div>
            </form>
        
        </div>
        </div>
    </div>
    <?php
}


elseif (isset($_GET['read'])) {
    // READ RECORD.
    $query = "SELECT * FROM hostvulns WHERE script_id=".intval($_GET['read']);
    $result = mysqli_query($connection, $query);
    confirm_query($result);
    $row = mysqli_fetch_assoc($result);

	// Find number of records.
	$query2 = "SELECT * FROM hostvulns";
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
                <h3 class="panel-title">Read Host Vulnerability</h3>
            </div>
            <div class="panel-body">

            <form class="form-horizontal" action="hostvulns.php" method="post">
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
                        <input type="text" class="form-control" name="findingID" value="<?php echo $c['finding'] ?>" readonly>
                    </div>
                </div>

                <div class="form-group">
                    <label class="col-sm-2 control-label">CVSS Base Score</label>
                    <div class="col-sm-2">
                        <input type="text" class="form-control" name="cvss_base" value="<?php echo $row['cvss_base'] ?>" readonly>
                    </div>
                </div>

                <div class="row">
                    <label class="col-sm-2 control-label">Internal</label>
                    <div class="col-sm-2">
                        <input type="text" class="form-control" name="internal" value="<?php echo $row['internal'] ?>" readonly>
                    </div>

                    <label class="col-sm-1 control-label">External</label>
                    <div class="col-sm-2">
                        <input type="text" class="form-control" name="external" value="<?php echo $row['external'] ?>" readonly>
                    </div>
                </div>
                <br>

                <div class="row">
                    <label class="col-sm-2 control-label">Published</label>
                    <div class="col-sm-2">
                        <input type="text" class="form-control" name="published" value="<?php echo $row['published'] ?>" readonly>
                    </div>

                    <label class="col-sm-1 control-label">Updated</label>
                    <div class="col-sm-2">
                        <input type="text" class="form-control" name="updated" value="<?php echo $row['updated'] ?>" readonly>
                    </div>
                </div>
                <br>

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
                    <a class="btn btn-default" href="hostvulns.php">Back</a>
                </div>
            </form>

            </div>
        </div>
    </div>
    <?php
}


elseif (isset($_GET['update'])) {
    // UPDATE RECORD.
    $query = "SELECT * FROM hostvulns WHERE script_id=".intval($_GET['update']);
    $result = mysqli_query($connection, $query);
    confirm_query($result);
    $row = mysqli_fetch_assoc($result);
    ?>

    <div class="container">
        <div class="panel panel-primary">
            <div class="panel-heading">
                <h3 class="panel-title">Update Host Vulnerability</h3>
            </div>	
            <div class="panel-body">

            <form class="form-horizontal" action="hostvulns.php" method="post">
                <input type = "hidden" name = "update" value = "<?php echo $row['script_id'] ?>">
                <div class="form-group">
                    <label class="col-sm-2 control-label">Tool</label>
                    <div class="col-sm-2">
                        <select class="form-control" name="tool">
                            <option value=""></option>
                            <option value="Nessus"<?php echo ($row['tool'] == 'Nessus' ? " selected" : "")?>>Nessus</option>
                            <option value="Nexpose"<?php echo ($row['tool'] == 'Nexpose' ? " selected" : "")?>>Nexpose</option>
                            <option value="Qualys"<?php echo ($row['tool'] == 'Qualys' ? " selected" : "")?>>Qualys</option>
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
                    $query = "SELECT * FROM findings WHERE type='Host' ORDER BY finding ASC";
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
                    <label class="col-sm-2 control-label">CVSS Base Score</label>
                    <div class="col-sm-2">
                        <input type="text" class="form-control" name="cvss_base" value="<?php echo $row['cvss_base'] ?>">
                    </div>
                </div>

                <div class="row">
                    <label class="col-sm-2 control-label">Internal</label>
                    <div class="col-sm-2">
                        <select class="form-control" name="internal">
                            <option value=""></option>
                            <option value="Critical"<?php echo ($row['internal'] == 'Critical' ? " selected" : "")?>>Critical</option>
                            <option value="High"<?php echo ($row['internal'] == 'High' ? " selected" : "")?>>High</option>
                            <option value="Medium"<?php echo ($row['internal'] == 'Medium' ? " selected" : "")?>>Medium</option>
                            <option value="Low"<?php echo ($row['internal'] == 'Low' ? " selected" : "")?>>Low</option>
                            <option value="Info"<?php echo ($row['internal'] == 'Info' ? " selected" : "")?>>Info</option>
                        </select>
                    </div>

                    <label class="col-sm-1 control-label">External</label>
                    <div class="col-sm-2">
                        <select class="form-control" name="external">
                            <option value=""></option>
                            <option value="Critical"<?php echo ($row['external'] == 'Critical' ? " selected" : "")?>>Critical</option>
                            <option value="High"<?php echo ($row['external'] == 'High' ? " selected" : "")?>>High</option>
                            <option value="Medium"<?php echo ($row['external'] == 'Medium' ? " selected" : "")?>>Medium</option>
                            <option value="Low"<?php echo ($row['external'] == 'Low' ? " selected" : "")?>>Low</option>
                            <option value="Info"<?php echo ($row['external'] == 'Info' ? " selected" : "")?>>Info</option>
                        </select>
                    </div>
                </div>
                <br>

                <div class="row">
                    <label class="col-sm-2 control-label">Published</label>
                    <div class="col-sm-2">
                        <input type="text" class="form-control" name="published" value="<?php echo $row['published'] ?>">
                    </div>

                    <label class="col-sm-1 control-label">Updated</label>
                    <div class="col-sm-2">
                        <input type="text" class="form-control" name="updated" value="<?php echo $row['updated'] ?>">
                    </div>
                </div>
                <br>

                <div class="form-group">
                    <label class="col-sm-2 control-label">Description</label>
                    <div class="col-sm-10">
                        <textarea class="form-control" name="description" rows="20"><?php echo $row['description'] ?></textarea>
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
                    <a class="btn btn-default" href="hostvulns.php">Back</a>
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
    <a class="btn btn-primary" href="hostvulns.php?create" input type="button">New</a>
    <br>
    <br>

    <?php
		// Number of rows per page.
		$rec_limit = 25;

		if (isset($_SESSION['rec_limit']))
			$rec_limit = $_SESSION['rec_limit'];

    	// Get the total number of records.
    	$query = "SELECT COUNT(vulnerability) FROM hostvulns";    
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
		$query = "SELECT * FROM hostvulns ORDER BY tool, vulnerability ASC LIMIT $offset, $rec_limit";
		$hostset = mysqli_query($connection, $query);
		confirm_query($result);
    ?>

    <table style="width: auto;" class="table table-bordered table-condensed table-hover">
        <tr>
            <th style="background-color:#E8E8E8; "</th>
            <th style="background-color:#E8E8E8; "</th>
            <th style="background-color:#E8E8E8; color:#0397B7; text-align:center;">Tool</th>
            <th style="background-color:#E8E8E8; color:#0397B7; text-align:center;">Host Vulnerability</th>
            <th style="background-color:#E8E8E8; color:#0397B7; text-align:center;">Finding Category</th>
            <th style="background-color:#E8E8E8; color:#0397B7; text-align:center;">CVSS</th>
            <th style="background-color:#E8E8E8; color:#0397B7; text-align:center;">Internal</th>
            <th style="background-color:#E8E8E8; color:#0397B7; text-align:center;">External</th>
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
                    <td width="50">'.'<a class="btn btn-primary" href="hostvulns.php?read='.$row['script_id'].'"><span class="glyphicon glyphicon-play"></span></a>'.'</td>
                    <td width="50">'.'<a class="btn btn-warning" href="hostvulns.php?update='.$row['script_id'].'"><span class="glyphicon glyphicon-pencil"></span></a>'.'</td>
                    <td width="100">'.$row["tool"].'</td>
                    <td width="500">'.$row["vulnerability"].'</td>
                    <td width="425">'.$finding["finding"].'</td>
                    <td width="100">'.$row["cvss_base"].'</td>
                    <td width="100">'.$row["internal"].'</td>
                    <td width="100">'.$row["external"].'</td>
                    <td width="150">'.$myDateFormat.'</td>
                    <td width="50">'.'<a class="btn btn-danger" href="hostvulns.php?delete='.$row['script_id'].'"
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
