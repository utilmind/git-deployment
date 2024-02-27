<?php
/**
    Git deployment script example by UtilMind.

    @see       https://github.com/utilmind/git-deployment/ The GitHub project
    @author    Oleksii Kuznietsov (utilmind) <utilmind@gmail.com>

    QUICK START:
        1. Rename this script into your project name.
        2. Modify the configuration options below ($CONFIG), according to your environment. (Don't forget to specify unique 'secret'.)
        3. Upload this script to your serer and point the URL to this script as WebHook.

        If you did everything right, your web project will be automatically updated from Git on every `git push`.
        All files and directory structure on your web server will be synchronized with the content in Git repository.
        Everything will be mirrored, everything what supposed to be deleted will be deleted.

        The good practice is to use code integrity checker, to monitor the code and inform administrator about all possible
        modifications outside of the Git repository (inform about possible malicious code injections, hacks).
        Use `code-integrity-checker.php` as example to monitor your live code.

    IMPORTANT!
        * You never need sudoer privileges when executing this script.   You never need sudo to pull updates from Git.
          if you think that you need it -- you're doing something wrong. ---------------------------------------------
          Anyway, the web user should NEVER have a super-privileges. Otherwise your web app is critically vulnerable.
        * Do not accidentally publish /.git directory. Keep it outside of any public_html’s.

    CONTRIBUTORS to original branch:
        * Please keep legacy PHP5 syntax;
        * Don't require any other libraries. Use only standard PHP5 functions.
**/

// -- CONFIGURATION --
$CONFIG = [
    'is_test' => false, // set to TRUE only to test, to skip authentication. Normally should be always FALSE.
    'allow_init_new_git' => true, // allow to initialize new local .git repository, if 'git_dir' doesn't exists. (Find 'git_dir' option below.)
    'log_output' => true, // log file name is 'this_script_name.log'.

    'secret' => '< Your $uper $ekret PaSsPhrase >', // use long passphrases with mix of alphanumeric and special ASCII characters!
    'git_addr' => 'git@github.com', // don't change for GitHub
    'remote_name' => 'origin',
    'default_branch' => 'master', // only for test mode. It automatically determinates the branch nage from Git.

    'git_dir' => '/path/to/local/repository', // + the /branch_name/ will be added automatically to this path
    'target_dir' => '/path/to/published/project', // should point to the root directory of your published project
    'repo_username' => 'YOUR_USERNAME',
    'repo_name' => 'YOUR_REPOSITORY_NAME',
];


// -- SHOW ALL ERRORS
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// -- No output buffering. Output immediately
@ini_set('output_buffering', 0);
@ini_set('zlib.output_compression', 0);
@ini_set('session.use_trans_sid', 0); // produce warning if session is active
ob_implicit_flush(1);
@ob_end_flush(); // it doesn't works (returns notice) on my local Windows PC, but required to start output without buffering
set_time_limit(900); // +15 minutes for execution. (Extend later if required!)
header('Content-type: text/plain'); // no HTML-formatting for output


// -- FUNCTIONS --
// Polyfill for PHP5-. https://stackoverflow.com/questions/27728674/php-call-of-undefined-function-hash-equals
if (!function_exists('hash_equals')) {
    function hash_equals($known_str, $user_str) {
        if (function_exists('mb_strlen')) {
            $kLen = mb_strlen($known_str, '8bit');
            $uLen = mb_strlen($user_str, '8bit');
        }else {
            $kLen = strlen($known_str);
            $uLen = strlen($user_str);
        }
        if ($kLen !== $uLen) {
            return false;
        }
        $result = 0;
        for ($i = 0; $i < $kLen; ++$i) {
            $result |= (ord($known_str[$i]) ^ ord($user_str[$i]));
        }
        // They are only identical strings if $result is exactly 0...
        return 0 === $result;
    }
}


/*  Returns string representation of IP. It can either IPv6 OR IPv4 format.
    Maximum length of returned value is 45 characters.

    Note: the type of determined IP depends on server. The same script can work differently on different server.
    Some servers addresses IPv6 representation only, some in both IPv4 and IPv6. It's not related to PHP. Check the settings of your HTTP server.
    See also
        IP functions: https://dev.mysql.com/doc/refman/5.6/en/miscellaneous-functions.html
        How to store IP as binary: https://dev.mysql.com/blog-archive/mysql-8-0-storing-ipv6/
*/
function get_ip() {
    if (!empty($_SERVER['HTTP_CLIENT_IP']) && (4 < strlen($_SERVER['HTTP_CLIENT_IP']))) {
        $ip = $_SERVER['HTTP_CLIENT_IP'];

    }elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR']) && (4 < strlen($_SERVER['HTTP_X_FORWARDED_FOR']))) {
        $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];

    }elseif (isset($_SERVER['REMOTE_ADDR'])) {
        $ip = $_SERVER['REMOTE_ADDR'];
    }else {
        $ip = false;
    }

    // If request forwarded via Proxy, there is can be multiple comma-separated addresses. And this can be in any value, even REMOTE_ADDR. Let's take only first.
    return $ip
        ? (false !== ($p = strpos($ip, ','))
            ? substr($ip, 0, $p)
            : $ip)
        : '0.0.0.0'; // It's '0:0:0:0:0:ffff:0:0' in IPv6, but this is impossible situation, so we don't care.
}

// Write to log + output as text
function print_log($msg, $http_exit_code = 0, $print_ip_time = false) { // script terminating if $http_exit_code specified
    global $CONFIG, $out, $log_name;

    $msg.= "\n";
    $out.= $msg;
    echo $msg;

    if ($CONFIG['log_output']) {
        file_put_contents(__DIR__."/$log_name.log",
            ($print_ip_time ? 'IP: '.get_ip().', '.date('r')."\n" : ''). // we output this when the process starts or on authentication errors.
            $msg.($http_exit_code ? "\n" : ''), FILE_APPEND); // make sure that this directory writeable for current user (DAEMON?)
    }

    // Terminate if any $http_exit_code specified.
    if ($http_exit_code) {
        if (200 !== $http_exit_code) {
            http_response_code($http_exit_code);
        }
        exit;
    }
}

// Execute command + output and log the result.
// Return value is result code
function exec_log($command) {
    print_log('>> '.$command);

    try { // We could use 'exec($command, $stdout, $result_code);', but we'd like to catch STDERR too.
        $proc = proc_open($command, [
                    1 => ['pipe', 'w'], // STDOUT
                    2 => ['pipe', 'w'], // STDERR
                ], $pipes);
        $stdout = stream_get_contents($pipes[1]);
        fclose($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[2]);

    }catch (Exception $e) {
        print_log("FATAL: failure on '$command'.", 500);

    }finally { // supported starting from PHP 5.5. If you can't use it -- just comment out 'finally' line and more proc_close() outside of 'finally'.
        $result_code = proc_close($proc);
    }

    // no sense to output $result_code here, it's always 0 (success) here.
    if (!empty($stderr)) { // Let's show errors first
        print_log('<< '.$stderr);
    }
    if (!empty($stdout)) {
        print_log($stdout);
    }

    if (0 !== $result_code) { // 0 is okay
        if (127 === $result_code) {
            print_log("ERROR: '$command' can't be executed. Command not found or not installed. Exiting.", 500); // nothing to execute?
            exit;
        }
        if (!$stdout) {
            print_log("ERROR: '$command' not executed? Empty output. Return value: $result_code.", 500);
        }
    }

    return $result_code;
}


// -- GO! --
$this_name = preg_replace('/\\.[^.\\s]{3,4}$/', '', basename($_SERVER['PHP_SELF']));

if ($CONFIG['is_test']) {
    $branch = $CONFIG['default_branch'];

}else {
    $log_name = $this_name.'-authentication-error';

    if (!isset($_POST['payload']) || (!$payload = json_decode($_POST['payload'], true)) || empty($payload['ref'])) {
        print_log('Bad request: no payload or bad payload', 400, true);
    }

    $ref = explode('/', $payload['ref']);
    if (!$branch = end($ref)) {
        print_log('No branch', 400, true);
    }

    $headers = function_exists('getallheaders') ? getallheaders() : []; // getallheaders() doesn't exists if script executed as CLI.
    if (count($headers)) {
        if ($CONFIG['log_output']) {
            file_put_contents(__DIR__.'/'.$this_name.'-request-headers.log', print_r($headers, true)."\n-- Payload:\n".print_r($payload, true)); // make sure that this directory writeable for current user (DAEMON?)
        }

        // make header keys lowercase (they are case insetive according to RFC 2616), and sometimes GitHub may send headers with different characters case.
        foreach ($headers as $k => $v) {
            unset($headers[$k]);
            $headers[strtolower($k)] = $v;
        }
    }

    if (!isset($headers['x-github-event'])) print_log('No service event', 400);
    if ($headers['x-github-event'] !== 'push') print_log('Wrong service event: '.$headers['x-github-event'], 400);

    $input = file_get_contents('php://input');
    if (!$input) print_log('No input', 400);

    // Verify signature
    if (isset($_POST['admin-key']) && ($key = $_POST['admin-key'])) {
        if (!password_verify($_KEYS['google_api_key'], '$2y$'.$key)) {
            print_log('Unauthorized', 403);
        }

    }elseif (!isset($headers['x-hub-signature-256']) ||
            !hash_equals('sha256='.hash_hmac('sha256', $input, $CONFIG['secret']), $headers['x-hub-signature-256'])) {
        print_log('Unauthorized', 403);
    }


    // -- RETURN --
    // Return output to GitHub before actual script execution. Idea: https://stackoverflow.com/questions/1019867/is-there-a-way-to-use-shell-exec-without-waiting-for-the-command-to-complete
    //ob_end_clean(); // if we'd have any output already
    ignore_user_abort();
    ob_start();
    header('Connection: close');
    header('Content-Length: '.ob_get_length());
    ob_end_flush();
    flush();
} // end if $CONFIG['is_test']


// Starting the process (authentication was successful already)
if ($CONFIG['log_output']) {
    $log_name = $this_name.'-'.$branch; // base name w/o extension. (We assume that extension is .php or .php5 or something... 3-4 characters.) + branch name.
    @unlink(__DIR__."/$log_name.log"); // clearing previous log
}

exec('whoami', $whoami, $retval);
print_log("Starting deployment of '$branch' branch into '$CONFIG[target_dir]' as user '$whoami[0]'...", 0, true);
$start_time = microtime(1);

chdir($git_dir = rtrim($CONFIG['git_dir'], '/').'/'.$branch); // switching into Git directory

if (is_dir($git_dir.'/.git')) {
    // If you need to discard all possible local changes: first "stash" them, then clear stash list.
    //git stash
    //git stash clear

    // But I prefer to do the "hard reset" instead of "stashing".
    exec_log("git --git-dir=\"$git_dir/.git\" --work-tree=\"$CONFIG[target_dir]\" reset --hard $CONFIG[remote_name]/$branch");
    // Switch to the correct branch for sure. It will respond something like "Already on 'master'" and this is fine.
    exec_log("git checkout $branch");

}elseif ($CONFIG['allow_init_new_git']) { // init repository from scratch, if it doesn't exists.
    exec_log("git init \"$git_dir\"");
    exec_log("git remote add $CONFIG[remote_name] $CONFIG[git_addr]-$CONFIG[repo_name]:$CONFIG[repo_username]/$CONFIG[repo_name].git");

    // "Prefetch" initially at least to see available branches
    exec_log('git fetch');

    // This discards all possible changes in local directory and pull everything from git
    exec_log("git --git-dir=\"$git_dir/.git\" --work-tree=\"$CONFIG[target_dir]\" reset --hard $CONFIG[remote_name]/$branch");
    // Set the branch to work with
    exec_log("git branch --set-upstream-to=$CONFIG[remote_name]/$branch $branch");

}else {
    print_log("Local .git directory doesn't exist in '$git_dir'. Please initialize local Git repository first, with specifying the remote origin, or allow initialization of new Git in the configuration.", 500);
}

// Fetch updates
$fetch_result = exec_log('git fetch');
if (0 !== $retval) {
    print_log("Git Fetch failed with exit code $retval.");
    if (128 === $retval) {
        print_log("Exit code 128 usually means that security credentials are invalid. CHECK YOUR DEPLOYMENT KEY! Is it listed in ~/.ssh? Access granted for 'ssh_config'? Is the key for user $whoami[0]?");
    }
}

// Go to the target directory to pull updates into it. Although we specifying the '--work-tree' option for 'pull', some Git versions seems ignoring this parameter.
chdir($CONFIG['target_dir']);

// Pull updates
$ret_val = exec_log("git --git-dir=\"$git_dir/.git\" --work-tree=\"$CONFIG[target_dir]\" pull $CONFIG[remote_name] $branch");
// Done
print_log("'git pull' finished with code $ret_val in ".number_format(microtime(1) - $start_time, 3).' seconds.', 200); // 0 is good!
