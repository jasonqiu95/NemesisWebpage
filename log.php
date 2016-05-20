<?php
$content = file_get_contents('php://input');
$data = json_decode($content, true);
print_r($data);
echo $content;
?>
