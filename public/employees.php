<?php
$bodyid = "employees";
include "../includes/header.php";
require_once("../includes/common.php");

if (isset($_POST['create'])) {
    // CREATE RECORD.

    // Check for blank field.
    $employee = trim($_POST['employee']);
    if (empty($employee)) { ?>
        <br>
        <button class="btn btn-danger" type="button"><strong>Warning!</strong> You must enter an employee.</button>
        <br><br>
        <a class="btn btn-default" href="employees.php?create" input type="button">Back</a>
        <?php exit;
    }

    $query = "INSERT INTO employees (modified, employee, title, type, accountmgr, projectmgr, cell, email, notes) VALUES (now(), '$_POST[employee]', '$_POST[title]', '$_POST[type]', '$_POST[accountmgr]', '$_POST[projectmgr]', '$_POST[cell]', '$_POST[email]', '$_POST[notes]')";
    $result = mysqli_query($connection, $query);
    confirm_query($result);
}


if (isset($_POST['update'])) {
    // UPDATE RECORD.
    $query = "UPDATE employees SET modified=now(), employee='$_POST[employee]', title='$_POST[title]', type='$_POST[type]', accountmgr='$_POST[accountmgr]', projectmgr='$_POST[projectmgr]', cell='$_POST[cell]', email='$_POST[email]', notes='$_POST[notes]' WHERE employeeID=".intval($_POST['update']);
  	$result = mysqli_query($connection, $query);
    confirm_query($result);
}


if (isset($_GET['delete'])) {
    // DELETE RECORD.
    $query = "DELETE FROM employees WHERE employeeID=".intval($_GET['delete']);
    $result = mysqli_query($connection, $query);
    confirm_query($result);
}


if (isset($_GET['create'])) {
    ?>
    <div class="container">
        <div class="panel panel-primary">
            <div class="panel-heading">
                <h3 class="panel-title">Create Employee</h3>
            </div>
        <div class="panel-body">

            <form class="form-horizontal" action="employees.php" method="post">
                <div class="form-group">
                    <label class="col-sm-2 control-label">Employee</label>
                    <div class="col-sm-10">
                        <input type="text" class="form-control" name="employee" placeholder="Employee">
                    </div>
                </div>

                <div class="form-group">
                    <label class="col-sm-2 control-label">Title</label>
                    <div class="col-sm-10">
                        <input type="text" class="form-control" name="title" placeholder="Title">
                    </div>
                </div>

                <div class="form-group">
                    <label class="col-sm-2 control-label">Type</label>
                    <div class="col-sm-2">
						<select class="form-control" name="type">
                            <option value=""></option>
                            <option value="Full Time">Full Time</option>
                            <option value="1099">1099</option>
						</select>
                    </div>
                </div>

                <div class="form-group">
                    <label class="col-sm-2 control-label">Account Mgr</label>
                    <div class="col-sm-2">
						<select class="form-control" name="accountmgr">
                            <option value=""></option>
                            <option value="Yes">Yes</option>
						</select>
                    </div>
                </div>

                <div class="form-group">
                    <label class="col-sm-2 control-label">Project Mgr</label>
                    <div class="col-sm-2">
						<select class="form-control" name="projectmgr">
                            <option value=""></option>
                            <option value="Yes">Yes</option>
						</select>
                    </div>
                </div>

                <div class="form-group">
                    <label class="col-sm-2 control-label">Cell</label>
                    <div class="col-sm-10">
                        <input type="text" class="form-control" name="cell" placeholder="Cell">
                    </div>
                </div>

                <div class="form-group">
                    <label class="col-sm-2 control-label">Email</label>
                    <div class="col-sm-10">
                        <input type="text" class="form-control" name="email" placeholder="Email">
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
                    <a class="btn btn-default" href="employees.php">Back</a>
                </div>
            </form>

        </div>
        </div>
    </div>
    <?php
}


elseif (isset($_GET['read'])) {
    // READ RECORD.
    $query = "SELECT * FROM employees WHERE employeeID=".intval($_GET['read']);
    $result = mysqli_query($connection, $query);
    confirm_query($result);
    $row = mysqli_fetch_assoc($result);

	// Find number of records.
	$query2 = "SELECT * FROM employees";
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
                <h3 class="panel-title">Read Employee</h3>
            </div>
            <div class="panel-body">

            <form class="form-horizontal" action="employees.php" method="post">
                <div class="form-group">
                    <label class="col-sm-2 control-label">Employee</label>
                    <div class="col-sm-10">
                        <input type="text" class="form-control" name="Employee" value="<?php echo $row['employee'] ?>" readonly>
                    </div>
                </div>

                <div class="form-group">
                    <label class="col-sm-2 control-label">Title</label>
                    <div class="col-sm-10">
                        <input type="text" class="form-control" name="title" value="<?php echo $row['title'] ?>" readonly>
                    </div>
                </div>

                <div class="form-group">
                    <label class="col-sm-2 control-label">Type</label>
                    <div class="col-sm-2">
                        <input type="text" class="form-control" name="type" value="<?php echo $row['type'] ?>" readonly>
                    </div>
                </div>

                <div class="form-group">
                    <label class="col-sm-2 control-label">Account Mgr</label>
                    <div class="col-sm-2">
                        <input type="text" class="form-control" name="accountmgr" value="<?php echo $row['accountmgr'] ?>" readonly>
                    </div>
                </div>

                <div class="form-group">
                    <label class="col-sm-2 control-label">Project Mgr</label>
                    <div class="col-sm-2">
                        <input type="text" class="form-control" name="projectmgr" value="<?php echo $row['projectmgr'] ?>" readonly>
                    </div>
                </div>

                <div class="form-group">
                    <label class="col-sm-2 control-label">Cell</label>
                    <div class="col-sm-10">
                        <input type="text" class="form-control" name="cell" value="<?php echo $row['cell'] ?>" readonly>
                    </div>
                </div>

                <div class="form-group">
                    <label class="col-sm-2 control-label">Email</label>
                    <div class="col-sm-10">
                        <input type="text" class="form-control" name="email" value="<?php echo $row['email'] ?>" readonly>
                    </div>
                </div>

                <div class="form-group">
                    <label class="col-sm-2 control-label">Notes</label>
                    <div class="col-sm-10">
                        <textarea class="form-control" name="notes" rows="6" readonly><?php echo $row['notes'] ?></textarea>
                    </div>
                </div>

                <div class="form-actions">
                    <a class="btn btn-default" href="employees.php">Back</a>
                </div>
            </form>

			</div>
		</div>
	</div>
    <?php
}


elseif (isset($_GET['update'])) {
    // UPDATE RECORD.
    $query = "SELECT * FROM employees WHERE employeeID=".intval($_GET['update']);
    $result = mysqli_query($connection, $query);
    confirm_query($result);
    $row = mysqli_fetch_assoc($result);
    ?>

    <div class="container">
        <div class="panel panel-primary">
            <div class="panel-heading">
                <h3 class="panel-title">Update Employee</h3>
            </div>
            <div class="panel-body">

            <form class="form-horizontal" action="employees.php" method="post">
				<input type = "hidden" name = "update" value = "<?php echo $row['employeeID'] ?>">
                <div class="form-group">
                    <label class="col-sm-2 control-label">Employee</label>
                    <div class="col-sm-10">
                        <input type="text" class="form-control" name="employee" value="<?php echo $row['employee'] ?>">
                    </div>
                </div>

                <div class="form-group">
                    <label class="col-sm-2 control-label">Title</label>
                    <div class="col-sm-10">
                        <input type="text" class="form-control" name="title" value="<?php echo $row['title'] ?>">
                    </div>
                </div>

                <div class="form-group">
                    <label class="col-sm-2 control-label">Type</label>
                    <div class="col-sm-2">
						<select class="form-control" name="type">
                            <option value=""></option>
                            <option value="Full Time"<?php echo ($row['type'] == 'Full Time' ? " selected" : "")?>>Full Time</option>
                            <option value="1099"<?php echo ($row['type'] == '1099' ? " selected" : "")?>>1099</option>
						</select>
                    </div>
                </div>

                <div class="form-group">
                    <label class="col-sm-2 control-label">Account Mgr</label>
                    <div class="col-sm-2">
						<select class="form-control" name="accountmgr">
                            <option value=""></option>
                            <option value="Yes"<?php echo ($row['accountmgr'] == 'Yes' ? " selected" : "")?>>Yes</option>
						</select>
                    </div>
                </div>

                <div class="form-group">
                    <label class="col-sm-2 control-label">Project Mgr</label>
                    <div class="col-sm-2">
						<select class="form-control" name="projectmgr">
                            <option value=""></option>
                            <option value="Yes"<?php echo ($row['projectmgr'] == 'Yes' ? " selected" : "")?>>Yes</option>
						</select>
                    </div>
                </div>

                <div class="form-group">
                    <label class="col-sm-2 control-label">Cell</label>
                    <div class="col-sm-10">
                        <input type="text" class="form-control" name="cell" value="<?php echo $row['cell'] ?>">
                    </div>
                </div>

                <div class="form-group">
                    <label class="col-sm-2 control-label">Email</label>
                    <div class="col-sm-10">
                        <input type="text" class="form-control" name="email" value="<?php echo $row['email'] ?>">
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
                    <a class="btn btn-default" href="employees.php">Back</a>
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
    <a class="btn btn-primary" href="employees.php?create" input type="button">New</a>
    <br>
    <br>

    <?php
        // Perform db query.
        $query = "SELECT * FROM employees ORDER BY employee ASC";
        $result = mysqli_query($connection, $query);
        confirm_query($result);
    ?>

    <table style="width: auto;" class="table table-bordered table-condensed table-hover">
        <tr>
            <th style="background-color:#E8E8E8;"></th>
            <th style="background-color:#E8E8E8;"></th>
            <th style="background-color:#E8E8E8; color:#0397B7; font-weight:bold; text-align:center;">Employee</th>
            <th style="background-color:#E8E8E8; color:#0397B7; font-weight:bold; text-align:center;">Title</th>
            <th style="background-color:#E8E8E8; color:#0397B7; font-weight:bold; text-align:center;">Cell</th>
            <th style="background-color:#E8E8E8; color:#0397B7; text-align:center;">Modified</th>
            <th style="background-color:#E8E8E8;"></th>
        </tr>

        <?php
            while($row = mysqli_fetch_assoc($result)) {
                $time = strtotime($row['modified']);
                $myDateFormat = date("m-d-y g:i A", $time);
                echo '
                <tr>
                    <td width="50">'.'<a class="btn btn-primary" href="employees.php?read='.$row['employeeID'].'"><span class="glyphicon glyphicon-play"></span></a>'.'</td>
                    <td width="50">'.'<a class="btn btn-warning" href="employees.php?update='.$row['employeeID'].'"><span class="glyphicon glyphicon-pencil"></span></a>'.'</td>
                    <td width="200">'.$row["employee"].'</td>
                    <td width="350">'.$row["title"].'</td>
                    <td width="125">'.$row["cell"].'</td>
                    <td width="175">'.$myDateFormat.'</td>
                    <td width="50">'.'<a class="btn btn-danger" href="employees.php?delete='.$row['employeeID'].'"
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
