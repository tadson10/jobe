<?php

/*
 * Copyright (C) 2014 Richard Lobb
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */


if ( ! defined('BASEPATH')) exit('No direct script access allowed');

require_once('application/libraries/REST_Controller.php');
require_once('application/libraries/LanguageTask.php');
require_once('application/libraries/JobException.php');
require_once('application/libraries/resultobject.php');
require_once('application/libraries/filecache.php');

define('MAX_READ', 4096);  // Max bytes to read in popen
define('MIN_FILE_IDENTIFIER_SIZE', 8);
define('LANGUAGE_CACHE_FILE', '/tmp/jobe_language_cache_file');

define('ACTIVE_PORTS', 2);  // The key for the shared memory active users array

class Restapi extends REST_Controller {
    static $PORT_IDS =  [[3000, ''], [3001, ''], [3002, ''], [3003, ''], [3004, ''], [3005, ''], [3006, ''], [3007, ''], [3008, ''], [3009, ''], [3010, '']];
    protected $languages = array();

    // Constructor loads the available languages from the libraries directory.
    // [But to handle CORS (Cross Origin Resource Sharing) it first issues
    // the access-control headers, and then quits if it's an OPTIONS request,
    // which is the "pre-flight" browser generated request to check access.]
    // See http://stackoverflow.com/questions/15602099/http-options-error-in-phil-sturgeons-codeigniter-restserver-and-backbone-js
    public function __construct()
    {
        header('Access-Control-Allow-Origin: *');
        header("Access-Control-Allow-Headers: X-API-KEY, Origin, X-Requested-With, Content-Type, Accept, Access-Control-Request-Method");
        header("Access-Control-Allow-Methods: GET, POST, OPTIONS, PUT, HEAD, DELETE");
        $method = $_SERVER['REQUEST_METHOD'];
        if($method == "OPTIONS") {
            die();
        }
        parent::__construct();

        $this->languages = $this->supported_languages();

        if ($this->config->item('rest_enable_limits')) {
            $this->load->config('per_method_limits');
            $limits = $this->config->item('per_method_limits');
            foreach ($limits as $method=>$limit) {
                $this->methods[$method]['limit'] = $limit;
            }
        }
    }


    protected function log($type, $message) {
        // Call log_message with the same parameters, but prefix the message
        // by *jobe* for easy identification.
        log_message($type, '*jobe* ' . $message);
    }


    protected function error($message, $httpCode=400) {
        // Generate the http response containing the given message with the given
        // HTTP response code. Log the error first.
        $this->log('error', $message);
        $this->response($message, $httpCode);
    }


    public function index_get() {
        $this->response('Please access this API via the runs, runresults, files or languages collections', 404);
    }

    // ****************************
    //         FILES
    // ****************************

    // Put (i.e. create or update) a file
    public function files_put($fileId=FALSE) {
        if ($fileId === FALSE) {
            $this->error('No file id in URL');
        }
        $contentsb64 = $this->put('file_contents', FALSE);
        if ($contentsb64 === FALSE) {
            $this->error('put: missing file_contents parameter');
        }

        $contents = base64_decode($contentsb64, TRUE);
        if ($contents === FALSE) {
            $this->error("put: contents of file $fileId are not valid base-64");
        }

        if (FileCache::file_put_contents($fileId, $contents) === FALSE) {
            $this->error("put: failed to write file $fileId to cache", 500);
        }
	
        $len = strlen($contents);
        $this->log('debug', "Put file $fileId, size $len");
        $this->response(NULL, 204);
    }

    //TadejS
    // Put (i.e. create or update) a file
    public function file_put($fileId=FALSE) {
        $response = array("message" => '', "port" => null, "jobeUser" => null, "randomValue" => null);
        
        // Check PORT reservation
        $port = $this->put("port", FALSE);
        $randomValue = $this->put("randomValue", FALSE);
        $jobeUser = $this->put("jobeUser", FALSE);

        $userSM = $this->getJobeUser($port, $jobeUser, $randomValue, TRUE);
        // $this->response($randomValue, 403);
        
        // Reservation doesn't exist
        if(!$userSM) {
            $response["message"] = "Reservation expired. Please reserve JOBE user and try again.";
            $response["port"] = $port;
            $response["jobeUser"] = $jobeUser;
            $response["randomValue"] = $randomValue;
    
            $this->response($response, 403);
        }

        // Nastavimo za primer, ko poleg API KEY pošlje uporabnik še CREDENTIALS, ki pa so lahko napačni
        $port = $userSM[5];
        $randomValue = $userSM[2];
        $jobeUser = $userSM[4];
        // $this->response($randomValue, 403);

        if ($fileId === FALSE) {
            $this->error('No file id in URL');
        }
        $contentsb64 = $this->put('file_contents', FALSE);
        if ($contentsb64 === FALSE) {
            $this->error('put: missing file_contents parameter');
        }

        $contents = base64_decode($contentsb64, TRUE);
        if ($contents === FALSE) {
            $this->error("put: contents of file $fileId are not valid base-64");
        }

        
        $dir = $jobeUser."_".$port."_".$randomValue;
        // All files except `app.js` are save in /public
        if($fileId != "app.js")
            $dir = $dir."/public";
        // $this->response(time(), 500);

        if (FileCache::save_file($fileId, $contents, $dir) === FALSE) {
            $this->error("put: failed to write file $fileId to cache", 500);
        }
	
        $len = strlen($contents);
        $this->log('debug', "Put file $fileId, size $len");
        $response["message"] = "File uploaded successfully!";
        $this->response($response, 201);
    }


    // Check file
    public function files_head($fileId) {
        if (!$fileId) {
            $this->error('head: missing file ID parameter in URL');
        } else if (FileCache::file_exists($fileId)) {
            $this->log('debug', "head: file $fileId exists");
            $this->response(NULL, 204);
        } else {
            $this->log('debug', "head: file $fileId not found");
            $this->response(NULL, 404);
        }
    }

    // Post file
    public function files_post() {
        $this->error('file_post: not implemented on this server', 403);
    }



    // ****************************
    //        STOP SERVER AT PORT
    // ****************************
    public function stop_post() {
        // Check PORT reservation
        $port = $this->post('port', FALSE);
        $jobeUser = $this->post('jobeUser', FALSE);
        $randomValue = $this->post('randomValue', FALSE);

        $userSM = $this->getJobeUser($port, $jobeUser, $randomValue, TRUE);
        // $this->response($userSM, 403);

        // Reservation doesn't exist
        if(!$userSM) {
            $odgovor["message"] = "Reservation expired. Please reserve JOBE user and try again.";
            $odgovor["port"] = $port;
            $odgovor["jobeUser"] = $jobeUser;
            $odgovor["randomValue"] = $randomValue;

            $this->response($odgovor, 403);
        }
        
        // $this->response($userSM, 403);

        // Nastavimo za primer, ko poleg API KEY pošlje uporabnik še CREDENTIALS, ki pa so lahko napačni
        $port = $userSM[5];
        $randomValue = $userSM[2];
        $jobeUser = $userSM[4];
        

        // $podatkiUstrezni = $this->preveriUstreznostPodatkov($port, $jobeUser, $randomValue);
        if($userSM) {
            exec("sudo /usr/bin/pkill -9 -u {$jobeUser}"); // Kill any remaining processes
            $this->response("Running processes for user " . $jobeUser . " were killed! " . $port . "_" . $jobeUser . "_" . $randomValue, 201);
        }
        else {
            $this->response("Invalid credentials for user " . $jobeUser . "!" . $port . "_" . $jobeUser . "_" . $randomValue, 201);
        }
/*
        if($port) {

            $pid = shell_exec("sudo lsof -t -i:".$port);
            //$this->response("sudo lsof -t -i:" . $port . " " . $port, 200);

            if($pid){
                $kill = shell_exec("sudo kill -9 " . $pid . " 2>&1");

                if(!$kill)
                    $this->response("Server uspešno ustavljen!", 200);
                else
                    $this->response("Prišlo je do napake pri ustavljanju serverja!", 400);
            }
            else {
                $this->response("No server is running at port " . $port . "! " . $jobeUser, 400);
            }
            
        }
        else {
            //Restapi::$PORT_IDS[0][1] = "BLA";
            $this->response('Port number is missing! ' . Restapi::$PORT_IDS[0][1], 400);
        }
        */
    }

    // ****************************
    //        RUNS
    // ****************************

    public function runs_get() {
        $id = $this->get('runId');
        $this->error('runs_get: no such run or run result discarded', 200);
    }


    public function runs_post() {
        $tmp = $this->post('run_spec', false);
        // $this->response($tmp, 400);
        $port = $tmp["port"];
        $jobeUser = $tmp["jobeUser"];
        $randomValue = $tmp["randomValue"];

        // $ustrezniPodatki = $this->preveriUstreznostPodatkov($port, $jobeUser, $randomValue);
        // if(!$ustrezniPodatki)
        //     $this->response("Reservation of port " . $port . " expired. Please, reserve another port.", 400);

        // Check if PORT reservation is valid
        $userSM = $this->getJobeUser($port, $jobeUser, $randomValue, TRUE);

        
        // Reservation doesn't exist
        if(!$userSM) {
            $odgovor["message"] = "Reservation expired. Please reserve JOBE user and try again.";
            $odgovor["port"] = $port;
            $odgovor["jobeUser"] = $jobeUser;
            $odgovor["randomValue"] = $randomValue;
    
            $this->response($odgovor, 403);
        }
        /*else{
            // $this->response($userSM, 403);
    
            // Nastavimo za primer, ko poleg API KEY pošlje uporabnik še CREDENTIALS, ki pa so lahko napačni
            $port = $userSM[5];
            $randomValue = $userSM[2];
            $jobeUser = $userSM[4];
        }*/
        // $this->response($userSM, 403);

        global $CI;

        // Note to help understand this method: the ->error and ->response methods
        // to not return. Then send the response then call exit().

        // Check this looks like a valid request.
        if (!$run = $this->post('run_spec', false)) {
            $this->error('runs_post: missing or invalid run_spec parameter', 400);
        }
        if (!is_array($run) || !isset($run['sourcecode']) ||
                !isset($run['language_id'])
        ) {
            $this->error('runs_post: invalid run specification', 400);
        }

        // REST_Controller has called to_array on the JSON decoded
        // object, so we must first turn it back into an object.
        $run = (object) $run;

        // If there are files, check them.
        if (isset($run->file_list)) {
            $files = $run->file_list;
            foreach ($files as $file) {
                if (!$this->is_valid_filespec($file)) {
                    $this->error("runs_post: invalid file specifier: " . print_r($file, true), 400);
                }
            }
        } else {
            $files = array();
        }
        

        // Get the the request languages and check it.
        $language = $run->language_id;
        if (!array_key_exists($language, $this->languages)) {
            $this->response("Language '$language' is not known", 400);
        }
        $reqdTaskClass = ucwords($language) . '_Task';
        if (!isset($run->sourcefilename) || $run->sourcefilename == 'prog.java') {
            // If no sourcefilename is given or if it's 'prog.java',
            // ask the language task to provide a source filename.
            // The prog.java is a special case (i.e. hack) to support legacy
            // CodeRunner versions that left it to Jobe to come up with
            // a name (and in Java it matters).
            $run->sourcefilename = '';
        }
        require_once($this->get_path_for_language_task($language));

        // Get any input.
        $input = isset($run->input) ? $run->input : '';

        // Get the parameters, and validate.
        $params = isset($run->parameters) ? $run->parameters : array();
        if (isset($params['cputime']) &&
                intval($params['cputime']) > intval($CI->config->item('cputime_upper_limit_secs'))
        ) {
            $this->response("cputime exceeds maximum allowed on this Jobe server", 400);
        }

        // Debugging is set either via a config parameter or, for a
        // specific run, by the run's debug attribute.
        // When debugging, the task run directory and its contents
        // are not deleted after the run.
        $debug = $this->config->item('debugging') ||
                (isset($run->debug) && $run->debug);



        // Create the task.
        $this->task = new $reqdTaskClass($run->sourcefilename, $input, $params);

        // The nested tries here are a bit ugly, but the point is that we want to
        // to clean up the task with close() before handling the exception.
        try {
            try {
                $this->task->prepare_execution_environment($run->sourcecode, $userSM);

                $this->task->load_files($files);

                $this->log('debug', "runs_post: compiling job {$this->task->id}");
                $this->task->compile();
                
                if (empty($this->task->cmpinfo)) {
                    $this->log('debug', "runs_post: executing job {$this->task->id}");
                    $this->task->execute();
                }

            } finally {
                // Delete task run directory unless it's a debug run
                $this->task->close(!$debug);
            }


            // Success!
            $this->log('debug', "runs_post: returning 200 OK for task {$this->task->id}");
            $this->response($this->task->resultObject(), 200);

        // Report any errors.
        } catch (JobException $e) {
            $this->log('debug', 'runs_post: ' . $e->getLogMessage());
            $this->response($e->getMessage(), $e->getHttpStatusCode());

        } catch (OverloadException $e) {
            $this->log('debug', 'runs_post: overload exception occurred');
            $resultobject = new ResultObject(0, Task::RESULT_SERVER_OVERLOAD);
            $this->response($resultobject, 200);

        } catch (Exception $e) {
            $this->response('Server exception (' . $e->getMessage() . ')', 500);
        }
    }

    // **********************
    //      RUN_RESULTS
    // **********************
    public function runresults_get()
    {
        $this->error('runresults_get: unimplemented, as all submissions run immediately.', 404);
    }

    // **********************
    //      FREE_PORTS
    // **********************
    // Function checks if all ports are used and removes reservations that has expired (1h)
    // Checks if we already have reservation for API KEY
    // If not it reserves PORT (and JOBE user) for this API KEY and returns credentials (port, jobeUser, randomValue)
    public function free_ports_post() {
        // $ip = 0;
        // if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
        //     $ip = $_SERVER['HTTP_CLIENT_IP'];
        // } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        //     $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
        // } else {
        //     $ip = $_SERVER['REMOTE_ADDR'];
        // }
        
        $odgovor = array("message" => '', "port" => null, "jobeUser" => null, "randomValue" => null);
        $apiKey = null;
        $isOldUser = false;

        $port = $this->post("port");
        $randomValue = $this->post("randomValue");
        $jobeUser = $this->post("jobeUser");

        // Check if all ports are used and remove those with expired reservation
        $array = $this->findAndRemoveExpiredPortReservations();
        $userSM = $this->getJobeUser($port, $jobeUser, $randomValue, FALSE);
        // We founnd reserved port for this user
        if($userSM)
            $isOldUser = true;

            //  $this->response($userSM, 201);

        // get API KEY from header
        /*$header = apache_request_headers(); 
            //  $this->response($header, 500);
        
        $apiKeyExists = array_key_exists("X-API-KEY", $header);//array_search("dcc9a835-9750-4725-af5b-2c839908f71", $header);
        // If API KEY exists, we check if reservation exists for this api key
        if($apiKeyExists) {
            $apiKey = $header["X-API-KEY"];
            //Check if port is already reserved
            $userSM = $this->getJobeUserByApiKeyAndCredentials($apiKey);
            
        }
        else {
            // TREBA PREGLEDATI, ALI OBSTAJA REZERVACIJO ZA KOMBINACIJO jobeUser_port_naključnaVrednost!
            // Pregledamo, ali je uporabnik v BODY poslal tudi port in nakljucno vrednost
            $port = $this->post("port");
            $randomValue = $this->post("randomValue");
            $jobeUser = $this->post("jobeUser");
            
            if($port && $randomValue && $jobeUser)
                $userSM = $this->getJobeUserByCredentials($port, $jobeUser, $randomValue);
            $this->response($this, 500);
        }*/
        
        

        // We didn't find reservation for user with this API KEY or CREDENTIALS
        if(!$isOldUser) {
            // get API KEY from header
            $header = apache_request_headers(); 
            $apiKeyExists = array_key_exists("X-API-KEY", $header);
            // If API KEY exists, we check if reservation exists for this api key
            if($apiKeyExists) {
                $apiKey = $header["X-API-KEY"];
            }

            // Get JOBE user
            require_once($this->get_path_for_language_task('nodejs'));
            $userId = FALSE;
            try {
                // Create the task.
                $task = new Nodejs_Task("", "", "");
                // $task->freeUser(0);

                // Allocate one of the Jobe users.
                $userSM = $task->getFreeUser($apiKey);
                $task = null;
            }
            catch (OverloadException $e) {
                $odgovor["message"] = 'No ports are available at the moment, please try again later!';
                $this->response($odgovor, 500);
            }
        }
        // else {
            
        //     $userId  = $isOldUser[6];
        //     $jobeUser = $isOldUser[4];
        // }
        // $jobeUser = sprintf("jobe%02d", $userId);
        // $this->response($isOldUser , 500);
        

        // read jobe user properties (credentials)
        $port = $userSM[5];       
        $jobeUser = $userSM[4];
        $randomValue = $userSM[2];
    

       
        
        // Create folder to reserve PORT
        // Folder is created when PORT is reserved for the first time
        // If it is OLD jobe user, we just send response
        $dir = $jobeUser."_".$port."_".$randomValue;
        if((!$isOldUser && mkdir("/home/jobe/runs/".$dir) && mkdir("/home/jobe/runs/".$dir."/public")) || $isOldUser) {
            // Če smo uspešno ustvarili mapo
            //vrnemo prosti port
            // $odgovor["message"] =  ;
            $odgovor["port"] = $port;
            $odgovor["jobeUser"] = $jobeUser;
            $odgovor["randomValue"] = $randomValue;             
            $this->response($odgovor, 200);
            // $this->response(implode(' | ', array_map('implode', $array, array_fill(0, count($array), ','))), 200);
        }
        else {
            // if($userId)
            //     $task->freeUser($userId);
            $odgovor["message"] = "Problem getting free port. Please try again later.";
            $this->response($odgovor, 500);

        }
        
/*
        // Napolnimo tabelo s porti in označimo vse kot neuporabljene (false)
        $dir = dir('/home/jobe/runs');
        $porti = [];
        for($i = 0; $i < 20; $i++) {
            $porti[$i] = [3000 + $i, false];
        }
        //$porti = [[3000, false], [3001, false], [3002, false], [3003, false], [3004, false], [3005, false], [3006, false], [3007, false], [3008, false], [3009, false]];
        $tmp = '';
        //Dobimo vse poddirektorije
        while (false !== ($entry = $dir->read())) {
            
            $array = explode("_", $entry);
            $port = intval($array[0]);
            $tmp = $tmp  . ', '. $port;
            //Shranimo port kot že uporabljen
            if($port != 0) {
                $porti[$port - 3000][1] = true;
            }
        }

        //Najdemo prvi neuporabljen port
        $port = null;
        for($i = 0; $i < count($porti); $i++) {
            if(!$porti[$i][1]) {
                $port = $porti[$i][0];
                break;
            }
        }
        $odgovor = array("message" => '', "port" => null, "jobeUser" => null, "randomValue" => null);
        
        //Ne najdemo prostega porta
        if(is_null($port)) {
            $odgovor["message"] = 'No ports are available at the moment, please try again later!';
            $this->response($odgovor, 404);
        }

        $str=rand(); 
        $randomValue = md5($str); 

        // Ustvarimo mapo, da rezerviramo PORT
        $dir = $port."_".$jobeUser."_".$randomValue;
        if(mkdir("/home/jobe/runs/".$dir)) {
            // Če smo uspešno ustvarili mapo
            //vrnemo prosti port
            $odgovor["port"] = $port;
            $odgovor["jobeUser"] = $jobeUser;
            $odgovor["randomValue"] = $randomValue;
            $this->response($odgovor, 200);
        }
        else {
            $task->freeUser($userId);
            $odgovor["message"] = "Problem getting free port. Please try again later.";
            $this->response($odgovor, 500);
        }*/
    }

    // Check if user for this API KEY and credentials already exists
    private function getJobeUser($port = FALSE, $jobeUser = FALSE, $randomValue = FALSE, $checkCred = TRUE) {
        $userSM = false;

        if(!$port || !$jobeUser || !$randomValue)
            return $userSM;
        
        
        // get API KEY from header
        $header = apache_request_headers(); 
        // $this->response($userSM, 201);

        $apiKey = $header["X-API-KEY"];
        //Check if port is already reserved
        $userSM = $this->getJobeUserByApiKeyAndCredentials($apiKey, $port, $jobeUser, $randomValue, $checkCred);
        
        return $userSM;
    }

    // Count the number of active users
    private function countActiveUsers($active = FALSE, $numUsers = 0) {
        $activeCount = 0;
        if(!$active)
            return $activeCount;
        
        for($i = 0; $i < $numUsers; $i++) {
            if($active[$i][0])
                $activeCount++;
        }

        return $activeCount;
    }

    // Check if any port reservation has expired (1h)
    // Reservation is removed only if all JOBE users are taken
    public function findAndRemoveExpiredPortReservations() {
        global $CI;

        $numUsers = $CI->config->item('jobe_max_users');

        $file = __FILE__;//"/var/www/html/jobe/application/controllers/Restapi.php";
        $key = ftok(__DIR__."/../libraries/LanguageTask.php", 'j');
        $sem = sem_get($key);
        sem_acquire($sem);
        $shm = shm_attach($key);
        $active = shm_get_var($shm, ACTIVE_USERS);

        // Check if all JOBE users are taken
        $areAllUsersTaken = ($this->countActiveUsers($active, $numUsers) == $numUsers) ? true : false;

        // Check if any port reservation has expired (1h)
        // Reservation is removed only if all JOBE users are taken
        for($i = 0; $i < $numUsers; $i++) {
            if($areAllUsersTaken && $active[$i][0] && intval($active[$i][1]) <= time()) {
                 $successfully = $this->removeDir($active[$i][5], $active[$i][4], $active[$i][2]);
                // if($successfully) {
                    $active[$i][0] = FALSE;
                    $active[$i][1] = null; //time
                    $active[$i][2] = null; //random value
                    $active[$i][3] = null; //api key
                    $active[$i][4] = null; //jobe user
                    $active[$i][5] = null; //port
            
                // }
                // 
            }
        }
        shm_put_var($shm, ACTIVE_USERS, $active);
        shm_detach($shm);
        sem_release($sem);

        return $active;
    }

    // Returns save credentials for JOBE user from SHARED MEMORY for this `API KEY`
    // $checkCred tells us if we have to check CREDENTIALS (when getting free port, we don't have to. But in every other situation we have to check it!)
    private function getJobeUserByApiKeyAndCredentials($apiKey = FALSE, $port = FALSE, $jobeUser = FALSE, $randomValue = FALSE, $checkCred = TRUE) {
        global $CI;

        if(!$apiKey)
            return null;

        $file = __FILE__;//"/var/www/html/jobe/application/controllers/Restapi.php";
        $key = ftok(__DIR__."/../libraries/LanguageTask.php", 'j');
        $sem = sem_get($key);
        sem_acquire($sem);
        $shm = shm_attach($key);
        $active = shm_get_var($shm, ACTIVE_USERS);
        
        shm_put_var($shm, ACTIVE_USERS, $active);
        shm_detach($shm);
        sem_release($sem);
        
        $numUsers = $CI->config->item('jobe_max_users');

        for($i = 0; $i < $numUsers; $i++) {
            if($active[$i][3] == $apiKey && (!$checkCred || ($checkCred && $active[$i][5] == $port && $active[$i][4] == $jobeUser && $active[$i][2] == $randomValue))) {
                // add index to object
                $tmp = $active[$i];
                $tmp[6] = $i;
                return $tmp;
            }
        }
        return false;
    }

     // Returns save credentials for JOBE user from SHARED MEMORY for those credentials
     private function getJobeUserByCredentials($port = FALSE, $jobeUser = FALSE, $randomValue = FALSE) {
        // global $CI;

        if(!$port || !$jobeUser || !$randomValue)
            return null;

        $file = __FILE__;//"/var/www/html/jobe/application/controllers/Restapi.php";
        $key = ftok(__DIR__."/../libraries/LanguageTask.php", 'j');
        $sem = sem_get($key);
        sem_acquire($sem);
        $shm = shm_attach($key);
        $active = shm_get_var($shm, ACTIVE_USERS);
        
        // shm_put_var($shm, ACTIVE_USERS, $active);
        shm_detach($shm);
        sem_release($sem);
        
        // $numUsers = $CI->config->item('jobe_max_users');
        // $userId = $port - 3000;
        $userId = (int)explode("jobe", $jobeUser)[1];

        //check if there is reservation for the CREDENTIALS
        if($active[$userId][2] == $randomValue && $active[$userId][4] == $jobeUser && $active[$userId][5] == $port) {
            // add index to object
            $tmp = $active[$userId];
            $tmp[6] = $userId;
            return $tmp;
        }
        
        return false;
    }
    

    //returns saved info for particular JOBE user with index = $jobeUserId
    private function getJobeUserByUserId($jobeUserId = FALSE) {
        if(!$jobeUserId && $jobeUserId != 0)
            return null;

        $file = __FILE__;//"/var/www/html/jobe/application/controllers/Restapi.php";
        $key = ftok(__DIR__."/../libraries/LanguageTask.php", 'j');
        $sem = sem_get($key);
        sem_acquire($sem);
        $shm = shm_attach($key);
        $active = shm_get_var($shm, ACTIVE_USERS);
        
        // shm_put_var($shm, ACTIVE_USERS, $active);
        shm_detach($shm);
        sem_release($sem);
        return $active[$jobeUserId];
    }

    // function removeDirectory($path) {

    //     $files = glob($path . '/*');
    //     foreach ($files as $file) {
    //         is_dir($file) ? removeDirectory($file) : unlink($file);
    //     }
    //     rmdir($path);
    
    //     return;
    // }

    // removes directory recursively for credential
    private function removeDir($port = FALSE, $jobeUser = FALSE, $randomValue = FALSE) {
        if(!$port && !$jobeUser && !$randomValue)
            return FALSE;
        
        // $port = 3000 + $jobeUserId;
        // $jobeUser = sprintf("jobe%02d", $jobeUserId);
        $dir = $jobeUser . "_" . $port . "_" .  $randomValue;

        // if we successfully delete directory or it doesn't exist
        if((is_dir("/home/jobe/runs/".$dir) && exec("sudo rm -R /home/jobe/runs/".$dir)) || !is_dir("/home/jobe/runs/".$dir))
            return TRUE;
        else
            return FALSE;
    }
// SE NE UPORABLJA - BO TREBA IZBRISATI!
    // // Reserve port in SHARED MEMORY
    // public function sharedMemory() {
    //     global $CI;

    //     $numPorts = $CI->config->item('jobe_max_users');
    //     $key = ftok(__FILE__,  "s");
    //     $sem = sem_get($key);
    //     $port = -1;
    //     $retries = 0;
    //     while ($port == -1) {  // Loop until we have a port (or an OverloadException is thrown)
    //         sem_acquire($sem);
    //         $shm = shm_attach($key);

    //         // PRVIČ - še ni inicializirano v SHARED MEMORY
    //         if (!shm_has_var($shm, ACTIVE_PORTS)) {
    //             // First time since boot -- initialise active list
    //             $active = array();
    //             for($i = 0; $i < $numPorts; $i++) {
    //                 $active[$i][0] = FALSE;
    //                 $active[$i][1] = null;
    //             }
    //             shm_put_var($shm, ACTIVE_PORTS, $active);
    //         }
    //         // pridobimo vrednost iz SHARED MEMORY
    //         $active = shm_get_var($shm, ACTIVE_PORTS);
    //         for ($port = 0; $port < $numPorts; $port++) {
    //             if (!$active[$port][0]) {
    //                 $active[$port][0] = TRUE;
    //                 $active[$port][1] = time();
    //                 shm_put_var($shm, ACTIVE_PORTS, $active);
    //                 break;
    //             }
    //         }
    //         shm_detach($shm);
    //         sem_release($sem);
    //         if ($port == $numPorts) {
    //             $port = -1;
    //             $retries += 1;
    //             if ($retries <= MAX_RETRIES) {
    //                 sleep(1);
    //             } else {
    //                 throw new OverloadException();
    //             }
    //         }
    //     }

    //     return $port;
    // }

    // public function preveriUstreznostPodatkov($port = FALSE, $jobeUser = FALSE, $randomValue = FALSE) {
    //     if(!$port || !$jobeUser || !$randomValue)
    //         return FALSE;

    //     //chdir('/home/jobe/runs');
    //     $dir = dir('/home/jobe/runs');
    //     $porti = [];
        
    //     $iskaniDir = $port . "_" . $jobeUser . "_" . $randomValue;
    //     //Dobimo vse poddirektorije
    //     while (false !== ($entry = $dir->read())) {
    //         if(strcmp($entry, $iskaniDir) == 0)
    //             return TRUE;
    //         // $array = explode("_", $entry);
    //         // $portDir = intval($array[0]);
            
    //     }
    //     return FALSE;
    // }

    // **********************
    //      LANGUAGES
    // **********************
    public function languages_get()
    {
        $this->log('debug', 'languages_get called');
        $languages = $this->supported_languages();
        $langs = array();
        foreach($languages as $lang => $version) {
            $langs[] = array($lang, $version);
        }
        $this->response($langs, 200);
    }

    // **********************
    // Support functions
    // **********************
    private function is_valid_filespec($file) {
        return (count($file) == 2 || count($file) == 3) &&
             is_string($file[0]) &&
             is_string($file[1]) &&
             strlen($file[0]) >= MIN_FILE_IDENTIFIER_SIZE &&
             ctype_alnum($file[0]) &&
             strlen($file[1]) > 0 &&
             ctype_alnum(str_replace(array('-', '_', '.'), '', $file[1]));
    }


    // Return an associative array mapping language name to language version
    // string for all supported languages (and only supported languages).
    private function supported_languages() {
        if (file_exists(LANGUAGE_CACHE_FILE)) {
            $langsJson = @file_get_contents(LANGUAGE_CACHE_FILE);
            $langs = json_decode($langsJson, true);

            // Security check, since this file is stored in /tmp where anyone could write it.
            foreach ($langs as $lang => $version) {
                if (!preg_match('/[a-z0-9]+/', $lang)) {
                    $langs = null; // Looks like the file has been tampered with, re-compute.
                    break;
                }
                if (!is_readable($this->get_path_for_language_task($lang))) {
                    $langs = null; // Looks like the file has been tampered with, re-compute.
                    break;
                }
            }
        }
        if (empty($langs) || (is_array($langs) && isset($langs[0]))) {
            $this->log('debug', 'Missing or corrupt languages cache file ... rebuilding it.');
            $langs = array();
            $library_files = scandir('application/libraries');
            foreach ($library_files as $file) {
                $end = '_task.php';
                $pos = strpos($file, $end);
                if ($pos == strlen($file) - strlen($end)) {
                    $lang = substr($file, 0, $pos);
                    require_once($this->get_path_for_language_task($lang));
                    $class = $lang . '_Task';
                    $version = $class::getVersion();
                    if ($version) {
                        $langs[$lang] = $version;
                    }
                }
            }

            $langsJson = json_encode($langs);
            file_put_contents(LANGUAGE_CACHE_FILE, $langsJson);
        }
        return $langs;
    }

    /**
     * Get the path to the file that defines the language task for a given language.
     *
     * @param $lang the language of interest, e.g. cpp.
     * @return string the corresponding code path.
     */
    private function get_path_for_language_task($lang) {
        return 'application/libraries/' . $lang . '_task.php';
    }
}
