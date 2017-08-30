<?php
$bodyid = "contacts";
include "../includes/header.php";
require_once("../includes/common.php");

if (isset($_POST['create'])) {
    // CREATE RECORD.

    // Check for blank field.
    $contact = trim($_POST['contact']);
    if (empty($contact)) { ?>
        <br>
        <button class="btn btn-danger" type="button"><strong>Warning!</strong> You must enter a contact.</button>
        <br><br>
        <a class="btn btn-default" href="contacts.php?create" input type="button">Back</a>
        <?php exit;
    }

    $query = "INSERT INTO contacts (modified, contact, clientID, title, work, cell, email, notes) VALUES (now(), '$_POST[contact]', '$_POST[clientID]', '$_POST[title]', '$_POST[work]', '$_POST[cell]', '$_POST[email]', '$_POST[notes]')";
    $result = mysqli_query($connection, $query);
    confirm_query($result);
}


if (isset($_POST['update'])) {
    // UPDATE RECORD.
    $query = "UPDATE contacts SET modified=now(), contact='$_POST[contact]', clientID='$_POST[clientID]', title='$_POST[title]', work='$_POST[work]', cell='$_POST[cell]', email='$_POST[email]', notes='$_POST[notes]' WHERE contactID=".intval($_POST['update']);
  	$result = mysqli_query($connection, $query);
    confirm_query($result);
}


if (isset($_GET['delete'])) {
    // DELETE RECORD.
    $query = "DELETE FROM contacts WHERE contactID=".intval($_GET['delete']);
    $result = mysqli_query($connection, $query);
    confirm_query($result);
}


if (isset($_GET['create'])) {
    ?>
    <div class="container">
        <div class="panel panel-primary">
            <div class="panel-heading">
                <h3 class="panel-title">Create Contact</h3>
            </div>

        <div class="panel-body">
            <form class="form-horizontal" action="contacts.php" method="post">
                <div class="form-group">
                    <label class="col-sm-2 control-label">Contact</label>
                    <div class="col-sm-10">
                        <input type="text" class="form-control" name="contact" placeholder="Contact">
                    </div>
                </div>

                <?php
                    $query = "SELECT * FROM clients ORDER BY client ASC";
                    $result = mysqli_query($connection, $query);
                    confirm_query($result);
                ?>

                <div class="form-group">
                    <label class="col-sm-2 control-label">Client</label>
                    <div class="col-sm-10">
						<select class="form-control" name="clientID">
                            <option value=""></option>
                            <?php
                            	while($c = mysqli_fetch_assoc($result)) {
                            		echo '<option value = "'.$c["clientID"].'">'.$c["client"].'</option>';
                            	}

                            	// Release returned data.
                            	mysqli_free_result($result);
                            ?>
						</select>
                    </div>
                </div>

                <div class="form-group">
                    <label class="col-sm-2 control-label">Title</label>
                    <div class="col-sm-10">
                        <input type="text" class="form-control" name="title" placeholder="Title">
                    </div>
                </div>

                <div class="form-group">
                    <label class="col-sm-2 control-label">Work</label>
                    <div class="col-sm-10">
                        <input type="text" class="form-control" name="work" placeholder="Work">
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
                    <a class="btn btn-default" href="contacts.php">Back</a>
                </div>
            </form>

        </div>
        </div>
    </div>
    <?php
}


elseif (isset($_GET['read'])) {
    // READ RECORD.
    $query = "SELECT * FROM contacts WHERE contactID=".intval($_GET['read']);
    $result = mysqli_query($connection, $query);
    confirm_query($result);
    $row = mysqli_fetch_assoc($result);
	
	// Find number of records.
	$query2 = "SELECT * FROM contacts";
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
                <h3 class="panel-title">Read Contact</h3>
            </div>
            <div class="panel-body">

            <form class="form-horizontal" action="contacts.php" method="post">
                <div class="form-group">
                    <label class="col-sm-2 control-label">Contact</label>
                    <div class="col-sm-10">
                        <input type="text" class="form-control" name="contact" value="<?php echo $row['contact'] ?>" readonly>
                    </div>
                </div>

                <div class="form-group">
                    <label class="col-sm-2 control-label">Client</label>
                    <div class="col-sm-10">
                        <input type="text" class="form-control" name="clientid" value="<?php echo $row['client'] ?>" readonly>
                    </div>
                </div>

                <div class="form-group">
                    <label class="col-sm-2 control-label">Title</label>
                    <div class="col-sm-10">
                        <input type="text" class="form-control" name="title" value="<?php echo $row['title'] ?>" readonly>
                    </div>
                </div>

                <div class="form-group">
                    <label class="col-sm-2 control-label">Work</label>
                    <div class="col-sm-10">
                        <input type="text" class="form-control" name="work" value="<?php echo $row['work'] ?>" readonly>
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
                    <a class="btn btn-default" href="contacts.php">Back</a>
                </div>
            </form>

			</div>
		</div>
	</div>
    <?php
}


elseif (isset($_GET['update'])) {
    // UPDATE RECORD.
    $query = "SELECT * FROM contacts WHERE contactID=".intval($_GET['update']);
    $result = mysqli_query($connection, $query);
    confirm_query($result);
    $row = mysqli_fetch_assoc($result);
    ?>

    <div class="container">
        <div class="panel panel-primary">
            <div class="panel-heading">
                <h3 class="panel-title">Update Contact</h3>
            </div>
            <div class="panel-body">

            <form class="form-horizontal" action="contacts.php" method="post">
				<input type = "hidden" name = "update" value = "<?php echo $row['contactID'] ?>">
                <div class="form-group">
                    <label class="col-sm-2 control-label">Contact</label>
                    <div class="col-sm-10">
                        <input type="text" class="form-control" name="contact" value="<?php echo $row['contact'] ?>">
                    </div>
                </div>

                <?php
                    $query = "SELECT * FROM clients ORDER BY client ASC";
                    $result = mysqli_query($connection, $query);
                    confirm_query($result);
                ?>

                <div class="form-group">
                    <label class="col-sm-2 control-label">Client</label>
                    <div class="col-sm-10">
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
                    <label class="col-sm-2 control-label">Title</label>
                    <div class="col-sm-10">
                        <input type="text" class="form-control" name="title" value="<?php echo $row['title'] ?>">
                    </div>
                </div>

                <div class="form-group">
                    <label class="col-sm-2 control-label">Work</label>
                    <div class="col-sm-10">
                        <input type="text" class="form-control" name="work" value="<?php echo $row['work'] ?>">
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
                    <a class="btn btn-default" href="contacts.php">Back</a>
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
    <a class="btn btn-primary" href="contacts.php?create" input type="button">New</a>
    <br>
    <br>

    <?php
        // Perform db query.
        $query = "SELECT * FROM contacts LEFT JOIN clients ON contacts.clientid=clients.clientid ORDER BY contact ASC";
        $result = mysqli_query($connection, $query);
        confirm_query($result);
    ?>

    <table style="width: auto;" class="table table-bordered table-condensed table-hover">
        <tr>
            <th style="background-color:#E8E8E8;"></th>
            <th style="background-color:#E8E8E8;"></th>
            <th style="background-color:#E8E8E8; color:#0397B7; font-weight:bold; text-align:center;">Contact</th>
            <th style="background-color:#E8E8E8; color:#0397B7; font-weight:bold; text-align:center;">Client</th>
            <th style="background-color:#E8E8E8; color:#0397B7; font-weight:bold; text-align:center;">Title</th>
            <th style="background-color:#E8E8E8; color:#0397B7; font-weight:bold; text-align:center;">Cell</th>
            <th style="background-color:#E8E8E8; color:#0397B7; text-align:center;">Modified</th>
            <th style="background-color:#E8E8E8;"></th>
        </tr>

        <?php
            while ($row = mysqli_fetch_assoc($result)) {
                $time = strtotime($row['modified']);
                $myDateFormat = date("m-d-y g:i A", $time);
				$query = "SELECT * FROM clients where clientID = ".intval($row['clientID']);
				$client = mysqli_query($connection, $query);
				confirm_query($client);
				$client = mysqli_fetch_assoc($client);

                echo '
                <tr>
                    <td width="50">'.'<a class="btn btn-primary" href="contacts.php?read='.$row['contactID'].'"><span class="glyphicon glyphicon-play"></span></a>'.'</td>
                    <td width="50">'.'<a class="btn btn-warning" href="contacts.php?update='.$row['contactID'].'"><span class="glyphicon glyphicon-pencil"></span></a>'.'</td>
                    <td width="200">'.$row["contact"].'</td>
                    <td width="300">'.$client['client'].'</td>
                    <td width="350">'.$row["title"].'</td>
                    <td width="125">'.$row["cell"].'</td>
                    <td width="175">'.$myDateFormat.'</td>
                    <td width="50">'.'<a class="btn btn-danger" href="contacts.php?delete='.$row['contactID'].'"
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
