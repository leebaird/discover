<?php
	$bodyid = "home";
	include "../includes/header.php";
	require_once("../includes/common.php");

    $query = "SELECT userID, username, email FROM users";

    try {
        $stmt = $db->prepare($query);
        $stmt->execute();
    }

    catch(PDOException $ex) {
        // On a production website, you should not output $ex->getMessage().
        die("Failed to run query: " . $ex->getMessage());
    }

    $rows = $stmt->fetchAll();

        $query = "SELECT * FROM users ORDER BY username ASC";
        $result = mysqli_query($connection, $query);
        confirm_query($result);

	if (isset($_GET['delete'])) {
    	// DELETE RECORD
    	$query = "DELETE FROM users WHERE userID=".intval($_GET['delete']);
    	$result = mysqli_query($connection, $query);
    	confirm_query($result);
	}
?>

<br><br><br>
<table style="width: auto;" class="table table-bordered table-condensed table-hover">
    <tr>
        <th style="background-color:#E8E8E8;"></th>
        <th style="background-color:#E8E8E8;"></th>
        <th style="background-color:#E8E8E8; color:#0397B7; font-weight:bold; text-align:center;">Username</th>
        <th style="background-color:#E8E8E8; color:#0397B7; font-weight:bold; text-align:center;">Email</th>
        <th style="background-color:#E8E8E8; color:#0397B7; font-weight:bold; text-align:center;">Role</th>
        <th style="background-color:#E8E8E8; color:#0397B7; font-weight:bold; text-align:center;">Approved</th>
        <th style="background-color:#E8E8E8; color:#0397B7; text-align:center;">Modified</th>
        <th style="background-color:#E8E8E8;"></th>
    </tr>

    <?php
        while($row = mysqli_fetch_assoc($result)) {
            $time = strtotime($row['modified']);
            $myDateFormat = date("m-d-y g:i A", $time);
			$query = "SELECT * FROM users where userID = ".intval($row['userID']);
			$finding = mysqli_query($connection, $query);
			confirm_query($finding);
			$finding = mysqli_fetch_assoc($finding);

            echo '
            <tr>
                <td width="50">'.'<a class="btn btn-primary" href="members.php?read='.$row['userID'].'"><span class="glyphicon glyphicon-play"></span></a>'.'</td>
                <td width="50">'.'<a class="btn btn-warning" href="members.php?update='.$row['userID'].'"><span class="glyphicon glyphicon-pencil"></span></a>'.'</td>
                <td width="200">'.$row["username"].'</td>
                <td width="300">'.$row["email"].'</td>
                <td width="100">'.$row["role"].'</td>
                <td width="100">'.$row["approved"].'</td>
                <td width="175">'.$myDateFormat.'</td>
                <td width="50">'.'<a class="btn btn-danger" href="members.php?delete='.$row['userID'].'"
                onclick="return confirm(\'Are you sure you want to delete this record?\');"><span class="glyphicon glyphicon-trash"></span></a>'.'</td>
            </tr>';
        }

        // Release returned data.
        mysqli_free_result($result);
    ?>

</table>

<?php include '../includes/footer.php'; ?>
