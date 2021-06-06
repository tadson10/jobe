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


if (!defined('BASEPATH')) exit('No direct script access allowed');

require_once('application/libraries/REST_Controller.php');
require_once('application/libraries/LanguageTask.php');
require_once('application/libraries/JobException.php');
require_once('application/libraries/resultobject.php');
require_once('application/libraries/filecache.php');

define('MAX_READ', 4096);  // Max bytes to read in popen
define('MIN_FILE_IDENTIFIER_SIZE', 8);
define('LANGUAGE_CACHE_FILE', '/tmp/jobe_language_cache_file');


/** 
 * @OA\Info(title="JOBE API", version="1.0")
 */

/**
 * @OA\SecurityScheme(
 *   securityScheme="ApiKeyAuthentication",
 *   type="apiKey",
 *   in="header",
 *   name="X-API-KEY"
 * )
 */

/**
 * @OA\Schema(schema="Unauthorized", 
 *  @OA\Property(property="status", type="boolean", description="Status of authorization", default=false),
 *  @OA\Property(property="error", type="string", description="Invalid api key", default="Invalid api key"))
 * 
 */

/**
 * @OA\Schema(schema="Language", 
 *  @OA\Property(property="language_id", type="string", description="Language id", default="nodejs"),
 *  @OA\Property(property="version", type="string", description="Version of language", default="10.23.3")
 * ) 
 */

/**
 *   @OA\Schema(schema="Credentials",
 *       @OA\Property(property="port", type="integer", description="Port that was assigned to user", defualt=3000),
 *       @OA\Property(property="jobeUser", type="string", description="Name of reserved JOBE user", default="jobe00"),
 *       @OA\Property(property="randomValue", type="string", description="Random value that was returned by server when reserving port", default="188f22c21baf49355ca26d3ed3da0bb8")
 *    ) 
 */


class Restapi extends REST_Controller {
    protected $languages = array();

    // Constructor loads the available languages from the libraries directory.
    // [But to handle CORS (Cross Origin Resource Sharing) it first issues
    // the access-control headers, and then quits if it's an OPTIONS request,
    // which is the "pre-flight" browser generated request to check access.]
    // See http://stackoverflow.com/questions/15602099/http-options-error-in-phil-sturgeons-codeigniter-restserver-and-backbone-js
    public function __construct() {
        header('Access-Control-Allow-Origin: *');
        header("Access-Control-Allow-Headers: X-API-KEY, Origin, X-Requested-With, Content-Type, Accept, Access-Control-Request-Method");
        header("Access-Control-Allow-Methods: GET, POST, OPTIONS, PUT, HEAD, DELETE");
        $method = $_SERVER['REQUEST_METHOD'];
        if ($method == "OPTIONS") {
            die();
        }
        parent::__construct();

        $this->languages = $this->supported_languages();

        if ($this->config->item('rest_enable_limits')) {
            $this->load->config('per_method_limits');
            $limits = $this->config->item('per_method_limits');
            foreach ($limits as $method => $limit) {
                $this->methods[$method]['limit'] = $limit;
            }
        }
    }


    protected function log($type, $message) {
        // Call log_message with the same parameters, but prefix the message
        // by *jobe* for easy identification.
        log_message($type, '*jobe* ' . $message);
    }


    protected function error($message, $httpCode = 400) {
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
    public function files_put($fileId = FALSE) {
        $this->response('Method is not currently available. Please use /file.', 404);

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


    /**
     * @OA\Put(path="/jobe/index.php/restapi/file/{fileName}", tags={"RestApi"},
     *   security={{"ApiKeyAuthentication":{}}},
     *   @OA\Parameter(name="fileName",
     *      in="path",
     *      required=true,
     *      @OA\Schema(type="string"),
     *      default="app.js"
     *   ),
     *  @OA\RequestBody(
     *      @OA\MediaType(
     *          mediaType="application/json",
     *          @OA\Schema(required={"port", "randomValue", "jobeUser", "file_contents"}, 
     *              @OA\Property(property="port", type="number", description="Port that was assigned to user", default=3000),
     *              @OA\Property(property="jobeUser", type="string", description="Name of reserved JOBE user", default="jobe00"),
     *              @OA\Property(property="randomValue", type="string", description="Random value that was returned by server when reserving port"),
     *              @OA\Property(property="file_contents", type="string", format="byte", description="File contents encoded in Base64", default="File contents encoded in Base64")
     * ) 
     *      )       
     *   ),
     *  @OA\Response (response="201", description="Success"),
     *  @OA\Response (response="403", description="Access denied", @OA\JsonContent(ref="#/components/schemas/Unauthorized"))
     * )
     */


    // Put (i.e. create or update) a file
    public function file_put($fileId = FALSE) {
        try {
            global $CI;

            // Check PORT reservation
            $port = $this->put("port", FALSE);
            $randomValue = $this->put("randomValue", FALSE);
            $jobeUser = $this->put("jobeUser", FALSE);

            $userSM = $this->getJobeUser($port, $jobeUser, $randomValue, TRUE);

            // Reservation doesn't exist
            if (!$userSM) {
                $this->response("Reservation expired. Please reserve JOBE user and try again.", 403);
            }

            if ($fileId === FALSE) {
                $this->error('No file id in URL');
            }
            $contentsb64 = $this->put('file_contents', FALSE);
            if ($contentsb64 === FALSE) {
                $this->error('put: missing file_contents parameter');
            }

            $contents = base64_decode($contentsb64, TRUE);
            $pattern = "/require\([\'\`\"](child_process|fs)[\'\`\"]\)/";
            if (preg_match($pattern, $contents) > 0) {
                $this->error("Using libraries <b>`child_process`</b> and <b>`fs`</b> is prohibited!");
            }

            if ($contents === FALSE) {
                $this->error("put: contents of file $fileId are not valid base-64");
            }

            $dir = $jobeUser . "_" . $port . "_" . $randomValue;

            // All files except `app.js` are saved in /public
            if ($fileId != "app.js") {
                $dir = $dir . "/public";

                // Count files
                if (!file_exists('/home/jobe/runs/' . $dir . '/' . $fileId)) {
                    $count = count(glob('/home/jobe/runs/' . $dir . "/*"));

                    $maxFiles = $CI->config->item('jobe_user_max_files') - 1;
                    if ($count >= $maxFiles) {
                        $this->error("You have reached maximum number of saved files per user!", 500);
                    }
                }
            }

            if (FileCache::save_file($fileId, $contents, $dir) === FALSE) {
                $this->error("Failed to save file <strong>$fileId</strong>.", 500);
            }

            $len = strlen($contents);
            $this->log('debug', "Put file $fileId, size $len");
            $this->response("File uploaded successfully!", 201);
        } catch (Throwable  $t) {
            $this->response("Error occurred while trying to save file to JOBE server. Please try again later.", 500);
        }
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
    //  STOP SERVER AT PORT
    // ****************************

    /**
     * @OA\Post(path="/jobe/index.php/restapi/stop", tags={"RestApi"},
     *   security={{"ApiKeyAuthentication":{}}},
     *  @OA\RequestBody(
     *       @OA\MediaType(
     *           mediaType="application/json",
     *           @OA\Schema(required={"port", "randomValue", "jobeUser"}, 
     *              @OA\Property(property="port", type="number", description="Port that was assigned to user", default=3000),
     *              @OA\Property(property="jobeUser", type="string", description="Name of reserved JOBE user", default="jobe00"),
     *              @OA\Property(property="randomValue", type="string", description="Random value that was returned by server when reserving port")
     * ) 
     *       )
     *   ),
     *  @OA\Response (response="200", description="Success"),
     *  @OA\Response (response="403", description="Access denied", @OA\JsonContent(ref="#/components/schemas/Unauthorized"))
     * )
     */
    public function stop_post() {
        try {
            // Check PORT reservation
            $port = $this->post('port', FALSE);
            $jobeUser = $this->post('jobeUser', FALSE);
            $randomValue = $this->post('randomValue', FALSE);

            $userSM = $this->getJobeUser($port, $jobeUser, $randomValue, TRUE);

            // Reservation doesn't exist
            if (!$userSM) {
                $this->response("Reservation expired. Please reserve JOBE user and try again.", 403);
            }

            // Get values directly from shared memory
            $port = $userSM[5];
            $randomValue = $userSM[2];
            $jobeUser = $userSM[4];

            if ($userSM) {
                exec("sudo /usr/bin/pkill -9 -u {$jobeUser}"); // Kill any remaining processes
                $this->response("Node.js app was stopped.", 200);
            } else {
                $this->response("JOBE user reservation expired.", 500);
            }
        } catch (Throwable $t) {
            $this->response("An error occured while trying to stop execution of NodeJS app.", 500);
        }
    }

    // ****************************
    //        RUNS
    // ****************************

    public function runs_get() {
        $id = $this->get('runId');
        $this->error('runs_get: no such run or run result discarded', 200);
    }

    //@OA\Schema(ref="#/components/schemas/Unauthorized")
    /**
     * @OA\Post(path="/jobe/index.php/restapi/runs", tags={"RestApi"},
     *   security={{"ApiKeyAuthentication":{}}},
     *  @OA\RequestBody(
     *       @OA\MediaType(
     *           mediaType="application/json",
     *           @OA\Schema(required={"port", "randomValue", "jobeUser"}, 
     *              @OA\Property(property="run_spec", type="object",
     *                  @OA\Property(property="port", type="number", description="Port that was assigned to user", default=3000),
     *                  @OA\Property(property="jobeUser", type="string", description="Name of reserved JOBE user", default="jobe00"),
     *                  @OA\Property(property="randomValue", type="string", description="Random value that was returned by server when reserving port"),
     *                  @OA\Property(property="language_id", type="string", default="nodejs", description="Language id - must be 'nodejs'"),
     *                  @OA\Property(property="sourcefilename", type="string", default="app", description="Name of the source file - must be 'app'"),
     *                  @OA\Property(property="parameters", type="object", @OA\Property(property="cputime", type="number", default=10, description="Maximux execution time"))
     *              )
     *          )    
     *       )
     *  ),
     *  @OA\Response (response="200", description="Success"),
     *  @OA\Response (response="403", description="Access denied", @OA\JsonContent(ref="#/components/schemas/Unauthorized"))
     * )
     */
    public function runs_post() {
        $tmp = $this->post('run_spec', false);
        $port = $tmp["port"];
        $jobeUser = $tmp["jobeUser"];
        $randomValue = $tmp["randomValue"];

        // Check if PORT reservation is valid
        $userSM = $this->getJobeUser($port, $jobeUser, $randomValue, TRUE);

        // Reservation doesn't exist
        if (!$userSM) {
            $this->response("Reservation expired. Please reserve JOBE user and try again.", 403);
        } else {
            // Check if anyone is using this port and kill all processes for that user
            // $userName = exec("sudo lsof -n -i :{$port} | awk '{print $3}' | tail -n1");
            // if ($userName != "") {
            exec("sudo /usr/bin/pkill -9 -u {$jobeUser}"); // Kill any remaining processes
            // }
        }

        global $CI;

        // Note to help understand this method: the ->error and ->response methods
        // to not return. Then send the response then call exit().

        // Check this looks like a valid request.
        if (!$run = $this->post('run_spec', false)) {
            $this->error('runs_post: missing or invalid run_spec parameter', 400);
        }
        if (!is_array($run) || !isset($run['language_id'])) {
            $this->error('runs_post: invalid run specification', 400);
        }
        if (isset($run['sourcefilename']) && !$this->is_valid_source_filename($run['sourcefilename'])) {
            $this->error('runs_post: invalid sourcefilename');
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
        if (
            isset($params['cputime']) &&
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
                $this->task->prepare_execution_environment($userSM);

                $this->task->load_files($files);

                $this->log('debug', "runs_post: compiling job {$this->task->id}");
                $this->task->compile();

                if (empty($this->task->cmpinfo)) {
                    $this->log('debug', "runs_post: executing job {$this->task->id}");
                    $this->task->execute($run);
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
    public function runresults_get() {
        $this->error('runresults_get: unimplemented, as all submissions run immediately.', 404);
    }

    // **********************
    //      FREE_PORTS
    // **********************
    /**
     * @OA\Get(path="/jobe/index.php/restapi/free_ports", tags={"RestApi"}, position=1,
     *  security={{"ApiKeyAuthentication":{}}},
     * @OA\Response (response="200", description="Success", @OA\JsonContent(ref="#/components/schemas/Credentials")),
     * @OA\Response (response="403", description="Access denied", @OA\JsonContent(ref="#/components/schemas/Unauthorized"))
     *  
     * )
     */
    // Function checks if all ports are used and removes reservations that has expired (1h)
    // Checks if we already have reservation for API KEY
    // If not it reserves PORT (and JOBE user) for this API KEY and returns credentials (port, jobeUser, randomValue)
    public function free_ports_get() {
        try {
            $apiKey = null;
            $isOldUser = false;

            $port = FALSE;
            $randomValue = FALSE;
            $jobeUser = FALSE;

            // Check if all ports are used and remove those with expired reservation
            $array = $this->findAndRemoveExpiredPortReservations();
            $userSM = $this->getJobeUser($port, $jobeUser, $randomValue, FALSE);
            // We founnd reserved port for this user
            if ($userSM)
                $isOldUser = true;

            // We didn't find reservation for user with this API KEY or CREDENTIALS
            if (!$isOldUser) {
                // get API KEY from header
                $header = apache_request_headers();
                $apiKeyExists = array_key_exists("X-API-KEY", $header);
                // If API KEY exists, we check if reservation exists for this api key
                if ($apiKeyExists) {
                    $apiKey = $header["X-API-KEY"];
                }

                // Get JOBE user
                require_once($this->get_path_for_language_task('nodejs'));
                try {
                    // Create the task.
                    $task = new Nodejs_Task("", "", "");

                    // Allocate one of the Jobe users.
                    $userSM = $task->getFreeUser($apiKey);
                    $task = null;
                } catch (OverloadException $e) {
                    $this->response('No Jobe user is available at the moment, please try again later!', 500);
                }
            }

            // read jobe user properties (credentials)
            $port = $userSM[5];
            $jobeUser = $userSM[4];
            $randomValue = $userSM[2];

            // Create folder to reserve PORT
            // Folder is created when PORT is reserved for the first time
            // If it is OLD jobe user, we just send response
            $dir = $jobeUser . "_" . $port . "_" . $randomValue;
            if ((!$isOldUser && mkdir("/home/jobe/runs/" . $dir, 0751) && mkdir("/home/jobe/runs/" . $dir . "/public",  0751)) || $isOldUser) {
                // If folder creation was successful
                // return credentials
                $response["port"] = $port;
                $response["jobeUser"] = $jobeUser;
                $response["randomValue"] = $randomValue;
                $this->response($response, 200);
            } else {
                $this->response("Problem getting free port. Please try again later.", 500);
            }
        } catch (Throwable $t) {
            $this->response("Problem reserving JOBE user.", 500);
        }
    }

    // Check if user for this API KEY and credentials already exists
    private function getJobeUser($port = FALSE, $jobeUser = FALSE, $randomValue = FALSE, $checkCred = TRUE) {
        $userSM = false;

        // if checkCred is TRUE and user didn't send any of the credentials, we return FALSE
        if ($checkCred && (!$port || !$jobeUser || !$randomValue))
            return $userSM;


        // get API KEY from header
        $header = apache_request_headers();

        $apiKey = $header["X-API-KEY"];
        //Check if port is already reserved
        $userSM = $this->getJobeUserByApiKeyAndCredentials($apiKey, $port, $jobeUser, $randomValue, $checkCred);

        return $userSM;
    }

    // Count the number of active users
    private function countActiveUsers($active = FALSE, $numUsers = 0) {
        $activeCount = 0;
        if (!$active)
            return $activeCount;

        for ($i = 0; $i < $numUsers; $i++) {
            if ($active[$i][0])
                $activeCount++;
        }

        return $activeCount;
    }

    // Check if list of users exists in SM and create it if it doesn't exist
    public function initialiseSharedMem($shm, $numUsers) {
        if (!shm_has_var($shm, ACTIVE_USERS)) {
            // First time since boot -- initialise active list
            $active = array();
            for ($i = 0; $i < $numUsers; $i++) {
                $active[$i][0] = FALSE;
                $active[$i][1] = null; //time
                $active[$i][2] = null; //random value
                $active[$i][3] = null; //api key
                $active[$i][4] = null; //jobe user
                $active[$i][5] = null; //port
            }
            shm_put_var($shm, ACTIVE_USERS, $active);

            // remove files of all users
            $successfully = is_dir("/home/jobe/runs") && exec("sudo rm -R /home/jobe/runs/*");
        }
    }
    // Check if any port reservation has expired (1h)
    // Reservation is removed only if all JOBE users are taken
    public function findAndRemoveExpiredPortReservations() {
        global $CI;

        $numUsers = $CI->config->item('jobe_max_users');

        $file = __FILE__; //"/var/www/html/jobe/application/controllers/Restapi.php";
        $key = ftok(__DIR__ . "/../libraries/LanguageTask.php", 'j');
        $sem = sem_get($key);
        sem_acquire($sem);
        $shm = shm_attach($key, 10000, 0600);

        // Check if list of jobe users exist in SM
        $this->initialiseSharedMem($shm, $numUsers);

        $active = shm_get_var($shm, ACTIVE_USERS);

        // Check if all JOBE users are taken
        $areAllUsersTaken = ($this->countActiveUsers($active, $numUsers) == $numUsers) ? true : false;

        // Check if any port reservation has expired (1h)
        // Reservation is removed only if all JOBE users are taken
        for ($i = 0; $i < $numUsers; $i++) {
            if ($areAllUsersTaken && $active[$i][0] && intval($active[$i][1]) <= time()) {
                $successfully = $this->removeDir($active[$i][5], $active[$i][4], $active[$i][2]);
                $active[$i][0] = FALSE;
                $active[$i][1] = null; //time
                $active[$i][2] = null; //random value
                $active[$i][3] = null; //api key
                $active[$i][4] = null; //jobe user
                $active[$i][5] = null; //port
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
        $numUsers = $CI->config->item('jobe_max_users');

        if (!$apiKey)
            return null;

        $file = __FILE__; //"/var/www/html/jobe/application/controllers/Restapi.php";
        $key = ftok(__DIR__ . "/../libraries/LanguageTask.php", 'j');
        $sem = sem_get($key);
        sem_acquire($sem);
        $shm = shm_attach($key, 10000, 0600);

        // Check if list of jobe users exist in SM
        $this->initialiseSharedMem($shm, $numUsers);

        $active = shm_get_var($shm, ACTIVE_USERS);
        shm_detach($shm);
        sem_release($sem);


        for ($i = 0; $i < $numUsers; $i++) {
            if ($active[$i][3] == $apiKey && (!$checkCred || ($checkCred && $active[$i][5] == $port && $active[$i][4] == $jobeUser && $active[$i][2] == $randomValue))) {
                // add index to object
                $tmp = $active[$i];
                $tmp[6] = $i;
                return $tmp;
            }
        }
        return false;
    }

    // removes directory recursively for credential
    private function removeDir($port = FALSE, $jobeUser = FALSE, $randomValue = FALSE) {
        if (!$port && !$jobeUser && !$randomValue)
            return FALSE;

        $dir = $jobeUser . "_" . $port . "_" .  $randomValue;

        // if we successfully delete directory or it doesn't exist
        if ((is_dir("/home/jobe/runs/" . $dir) && exec("sudo rm -R /home/jobe/runs/" . $dir)) || !is_dir("/home/jobe/runs/" . $dir))
            return TRUE;
        else
            return FALSE;
    }

    // **********************
    //      LANGUAGES
    // **********************

    /**
     * @OA\Get(path="/jobe/index.php/restapi/languages", tags={"RestApi"},
     *  @OA\Response (response="200", description="Success", @OA\JsonContent(type="array", @OA\Items(ref="#/components/schemas/Language"))),
     *  @OA\Response (response="403", description="Access denied", @OA\JsonContent(ref="#/components/schemas/Unauthorized")),
     *  security={{"ApiKeyAuthentication":{}}}
     * )
     */

    public function languages_get() {
        $this->log('debug', 'languages_get called');
        $languages = $this->supported_languages();
        $langs = array();
        foreach ($languages as $lang => $version) {
            $langObj["language_id"] = $lang;
            $langObj["version"] = $version;
            $langs[] = $langObj;
        }
        $this->response($langs, 200);
    }

    // **********************
    // Support functions
    // **********************

    // Return true unless the given filename looks dangerous, e.g. has '/' or '..'
    // substrings. Uses code from https://stackoverflow.com/questions/2021624/string-sanitizer-for-filename
    private function is_valid_source_filename($filename) {
        $sanitised = preg_replace(
            '~
        [<>:"/\\|?*]|            # file system reserved https://en.wikipedia.org/wiki/Filename#Reserved_characters_and_words
        [\x00-\x1F]|             # control characters http://msdn.microsoft.com/en-us/library/windows/desktop/aa365247%28v=vs.85%29.aspx
        [\x7F\xA0\xAD]|          # non-printing characters DEL, NO-BREAK SPACE, SOFT HYPHEN
        [#\[\]@!$&\'()+,;=]|     # URI reserved https://tools.ietf.org/html/rfc3986#section-2.2
        [{}^\~`]                 # URL unsafe characters https://www.ietf.org/rfc/rfc1738.txt
        ~x',
            '-',
            $filename
        );
        // Avoid ".", ".." or ".hiddenFiles"
        $sanitised = ltrim($sanitised, '.-');
        return $sanitised === $filename;
    }

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
