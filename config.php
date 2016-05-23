<?php

include('core/inc/functions.php');
include('core/Collection.php');
include('core/DB.php');
include('core/DB_Table.php');
include('core/Hash.php');
include('core/LinkedCollection.php');
include('core/Log.php');
include('core/UserBase.php');
include('core/User.php');

//Instantiate the uFlex User object
$user = new \nemesis\User();

//Add database credentials and information
$user->config->database->host = "localhost";
$user->config->database->user = "n8lmcn5_nemesis";
$user->config->database->password = "qcszhnemesis2016";
$user->config->database->name = "n8lmcn5_nemesis"; //Database name

/*
 * Instead of editing the Class files directly you may make
 * the changes in this space before calling the ->start() method.
 * For example: if we want to change the default Username from "Guess"
 * to "Stranger" you do this:
 *
 * $user->config->userDefaultData->Username = 'Stranger';
 *
 * You may change and customize all the options and configurations like
 * this, even the error messages. By exporting your customizations outside
 * the class file it will be easier to maintain your application configuration
 * and update the class core itself in the future.
 */

//Starts the object by triggering the constructor
$user->start();
?>
