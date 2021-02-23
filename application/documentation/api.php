<?php
header('Access-Control-Allow-Origin: *');
require("../../vendor/autoload.php");
$openapi = \OpenApi\scan("../controllers");
header('Content-Type: application/json');
echo $openapi->toJson();
