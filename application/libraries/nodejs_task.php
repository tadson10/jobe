<?php defined('BASEPATH') or exit('No direct script access allowed');

/* ==============================================================
 *
 * Node-js
 *
 * ==============================================================
 *
 * @copyright  2014 Richard Lobb, University of Canterbury
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

require_once('application/libraries/LanguageTask.php');

class Nodejs_Task extends Task {
    public function __construct($filename, $input, $params) {
        parent::__construct($filename, $input, $params);
        $this->default_params['memorylimit'] = 650; // Need more for numpy

        $this->default_params['interpreterargs'] = array('--use_strict');
    }

    public static function getVersionCommand() {
        return array('nodejs --version', '/v([0-9._]*)/');
    }

    public function compile() {
        $this->executableFileName = $this->sourceFileName;
        if (!file_exists($this->sourceFileName)) {
            throw new Exception("Node_Task: File " . $this->sourceFileName . " doesn't exist.");
        }
    }


    // A default name forjs programs
    public function defaultFileName($sourcecode) {
        return 'prog.js';
    }

    public function getExecutablePath() {
        return '/usr/bin/nodejs';
    }


    public function getTargetFile() {
        return $this->sourceFileName;
    }
}
