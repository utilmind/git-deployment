<?php
/***
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
        * Don't require any other libraries. Use only standard functions.

    MISCELLANEOUS TIPS:
        * How to create Deploy key: https://docs.github.com/en/authentication/connecting-to-github-with-ssh/managing-deploy-keys#deploy-keys
            Briefly...
                1. Generate key:
                    ssh-keygen -t ed25519 -C "<email@address>" -f <key_file_name>
                2. Add key to ssh-agent:
                    eval "$(ssh-agent -s)"
                    ssh-add ~/.ssh/<key_file_name>
                3. Open /etc/ssh/ssh_config (or create new file in "/etc/ssh/ssh_config/ssh_config.d/" if your ssh_config including files in "ssh_config.d" directory, or use local config "~/.ssh/config")
                   Add some record like follows:
                        Host <git_hostname, eg. github.com or bitbucket.org>-<your_repository_name>
                          HostName <git_hostname, eg. github.com or bitbucket.org>
                          IdentityFile ~/.ssh/<key_file_name>
                          IdentitiesOnly yes

        * Always generate SSH key for web user only (e.g. www-data or deamon, depending which username execute scripts in your HTTP server, depending which user executing this deployment script).

        * Your deployment directory must be write-accessible for the web-user.
***/
// -- SHOW ALL ERRORS (even before the config)
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);


// -- CONFIGURATION --
$CONFIG = [
    'is_test'       => false, // set to TRUE only to test, to skip authentication. Normally should be always FALSE.
    'allow_init_new_git' => true, // allow to initialize new local .git repository, if 'git_dir' doesn't exists. (Find 'git_dir' option below.)
    'log_output'    => true, // log file name is 'this_script_name.log'.

     // !! Don't keep any secrets and passwords in Git, use some environment variable instead.
    'secret'        => '< Your $uper $ekret PaSsPhrase >', // use long passphrases with the mix of alphanumeric and special ASCII characters!

    'git_host'      => 'github.com', // don't change if we fetching repo from GitHub. This domain adding to "~/.ssh/known_hosts" on first fetching.
    'git_addr'      => 'git@github.com', // don't change for GitHub
    'known_hosts'   => ($_SERVER['HOME'] ?? '~').'/.ssh/known_hosts', // location of "known_hosts". Use full path, ~ in '~/.ssh/known_hosts' is not interpreted by PHP. Usually specified path should not be changed. We adding the fingerprint of 'git_host' into the list of known_hosts to avoid confirmation via CLI.
    'remote_name'   => 'origin',
    'default_branch'=> 'master', // only for test mode. It automatically determinates the branch nage from Git.

    // You will need to set up write permission for the following directories.
    // Get web username with $_SERVER['LOGNAME'] ?? $_SERVER['USER'] ?? $_SERVER['USERNAME']; // (from $_SERVER['USER'] on Ubuntu/Nginx).
    'git_dir'       => '/path/to/local/repository', // + the /branch_name/ will be added automatically to this path
    'target_dir'    => '/path/to/published/project', // should point to the root directory of your published project
    'repo_username' => 'YOUR_USERNAME',
    'repo_name'     => 'YOUR_REPOSITORY_NAME',

    'log_path'      => __DIR__.'/logs/', // must have trailing /. Make sure that it's writeable for the web user (e.g. www-data, daemon)
];


// -- No output buffering. Output immediately
@ini_set('output_buffering', 0);
@ini_set('zlib.output_compression', 0);
@ini_set('session.use_trans_sid', 0); // produce warning if session is active
ob_implicit_flush(1);
@ob_end_flush(); // it doesn't works (returns notice) on my local Windows PC, but required to start output without buffering
set_time_limit(900); // +15 minutes for execution. (Extend later if required!)
header('Content-type: text/plain'); // no HTML-formatting for output
ob_start(); // to catch all errors

// -- FUNCTIONS --
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
function print_log($msg, $http_exit_code = 0) { // if $http_exit_code specified, then script terminating (exiting).
    global $CONFIG, $out, $log_name;

    $msg.= "\n";
    $out.= $msg;

    if ($CONFIG['log_output']) {
        static $is_first_output = true; // AK: we want to log IP and date in start.

        $log = $msg;
        // IP and date are only for the log file. They are not needed in stdout.
        if ($is_first_output) {
            $is_first_output = false;
            $log = 'IP: '.get_ip().', '.date('r')."\n$log"; // we output this when the process starts or on authentication errors.
        }
        if ($http_exit_code) {
            $log .= "\n"; // one more line separator in log
        }

        file_put_contents("$CONFIG[log_path]$log_name.log", $log, FILE_APPEND);
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
function exec_log($command, $ignore_empty_stdout = false, $debug_stderr = false) {
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
                if (6 < time() - $start_time) { // AK: I think 6 seconds is enough. But feel free to adjust.
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
        }
        if (!$stdout) {
            print_log("ERROR: '$command' not executed? Empty output. Return value: $result_code.", $ignore_empty_stdout ? null : 500);
        }
    }

    return $result_code;
}


// -- GO! --
$this_name = preg_replace('/\\.[^.\\s]{3,4}$/', '', basename($_SERVER['PHP_SELF']));
$branch = $CONFIG['default_branch']; // default, while it's not determined yet.

// VALIDATION... (We don't want to give any output before request validated. Except errors, of course.)
if (!$CONFIG['is_test']) {
    $log_name = $this_name.'-authentication-error';

    // Check POSTed data
    switch ($CONFIG['git_host']) {
        case 'github.com':
            if (!isset($_POST['payload']) || (!$payload = json_decode($_POST['payload'], true)) || empty($payload['ref'])) {
                print_log("Bad request: no payload or bad payload.\n".print_r($_POST, true)."\n".print_r($headers, true), 400);
            }

            $ref = explode('/', $payload['ref']);
            if (!$branch = end($ref)) {
                print_log('No branch', 400);
            }
            break;

        // 'bitbucket.org' doesn't POST anything. We can determinate branch from php://input
    }


    // Check HTTP headers
    $headers = function_exists('getallheaders') ? getallheaders() : []; // getallheaders() doesn't exists if script executed as CLI.
    if (count($headers)) {
        if ($CONFIG['log_output']) {
            file_put_contents("$CONFIG[log_path]$this_name-request-headers.log",
                    print_r($headers, true)
                        // if have POSTed payload (e.g. from GitHub)
                        . (isset($payload)
                                ? "\n-- Payload:\n".print_r($payload, true)
                                : '')
                );
        }

        // make header keys lowercase (they are case insetive according to RFC 2616), and sometimes GitHub may send headers with different characters case.
        foreach ($headers as $k => $v) {
            unset($headers[$k]);
            $headers[strtolower($k)] = $v;
        }
    }

    switch ($CONFIG['git_host']) {
        case 'github.com':
            if (!isset($headers['x-github-event'])) {
                print_log('No service event', 400);
            }
            $is_push = 'push' === $headers['x-github-event'];

        case 'bitbucket.org':
            if (!isset($headers['x-event-key'])) {
                print_log('No service event', 400);
            }
            $is_push = 'repo:push' === $headers['x-event-key'];
    }

    if (!$is_push) {
        print_log('Wrong service event: '.$service_event, 400);
    }

    if (!$input = file_get_contents('php://input')) {
        print_log('No input', 400);
    }

    if ($CONFIG['log_output']) {
        file_put_contents("$CONFIG[log_path]$this_name-request-input.log", $input);
    }

    // Verify POSTed admin-key (AK: This should be deprecated. Avoid using this.)
    if (isset($_POST['admin-key']) && ($key = $_POST['admin-key']) && isset($_KEYS['google_api_key'])) {
        if (!password_verify($_KEYS['google_api_key'], '$2y$'.$key)) {
            print_log('Bad admin key', 401);
        }

    // Verify signature
    }elseif ((!$signature = $headers['x-hub-signature-256'] ?? $headers['x-hub-signature'] ?? '')
                // Polyfill of hash_equals() for PHP5-. https://stackoverflow.com/questions/27728674/php-call-of-undefined-function-hash-equals
                || !hash_equals('sha256='.hash_hmac('sha256', $input, $CONFIG['secret']), $signature)) {
        print_log('Unauthorized', 401);
    }


    // -- RETURN --
    // Return output to Git before the actual script execution. Idea: https://stackoverflow.com/questions/1019867/is-there-a-way-to-use-shell-exec-without-waiting-for-the-command-to-complete
    ignore_user_abort(true);
    ob_end_flush();
    header('Connection: close'); // mb also header('Content-Length: 0'), but this is wrong. Apache terminates connection and close STDOUT buffer after getting these headers.
    flush(); // AK: but there is nothing to flush?

    if (function_exists('fastcgi_finish_request')) {
        fastcgi_finish_request();
    }
} // end if $CONFIG['is_test']


// Starting the process (authentication was successful already)
if ($CONFIG['log_output']) {
    $log_name = $this_name.'-'.$branch; // base name w/o extension. (We assume that extension is .php or .php5 or something... 3-4 characters.) + branch name.
    @unlink(__DIR__."/$log_name.log"); // clearing previous log
}

$current_user = $_SERVER['LOGNAME'] ?? $_SERVER['USER'] ?? $_SERVER['USERNAME'] ?? '';
if (!$current_user) { // It can be still not defined on Apache.
    exec('whoami', $whoami, $retval);
    $current_user = $whoami[0];
}

// Bitbucket wants some output immediately. So giving this before starting output buffer...
print_log("Starting deployment of '$branch' branch into '$CONFIG[target_dir]' as user $current_user...");
$start_time = microtime(true);
ob_start(); // to catch all further errors
try {
    $git_dir = rtrim($CONFIG['git_dir'], '/').'/'.$branch;
    if (!is_dir($git_dir.'/.git')) {
        if ($CONFIG['allow_init_new_git']) {
            exec_log("git init \"$git_dir\"");

            /* $CONFIG[git_addr]-$CONFIG[repo_name] is the record in your /etc/ssh/ssh_config.
            The typical record looks like follows:

                    Host bitbucket.org-repository_name
                    HostName bitbucket.org
                    IdentityFile ~/.ssh/id_ed25519_avmet
                    IdentitiesOnly yes

            If you use record different than "[git_addr]-[repo_name]", please update it accordingly. In some cases you may need just [git_addr] w/o -[repo_name].
            */
            exec_log("git remote add $CONFIG[remote_name] $CONFIG[git_addr]-$CONFIG[repo_name]:$CONFIG[repo_username]/$CONFIG[repo_name].git"); // add origin (or whatever 'remote_name')

            // Check, whether 'git_host' already listed in "~/.ssh/known_hosts"... (must be writeable for $current_user!!)
            $CONFIG['known_hosts'] = strtolower($CONFIG['known_hosts']); // just for sure
            if (!file_exists($CONFIG['known_hosts']) // AK: if file exists, but we can't verify this or can't get contents, check 'open_basedir' restrictions.
                        || (!$file_content = file_get_contents($CONFIG['known_hosts']))
                        || (false === strpos($file_content, $CONFIG['git_host'].' ssh-rsa'))) { // any string to identify whether fingerprint already included within known_hosts.
                // Add GitHub (or another host for repository) to the list of known_hosts, so it will not ask to confirm fingerprint in CLI.
                // Read more about auto-confirmation for the fingerprint on https://serverfault.com/questions/447028/non-interactive-git-clone-ssh-fingerprint-prompt
                exec_log("ssh-keyscan $CONFIG[git_host] >> $CONFIG[known_hosts]");
            }

        }else {
            print_log("Local .git directory doesn't exist in '$git_dir'. Please initialize local Git repository first, with specifying the remote origin, or allow initialization of new Git in the configuration.", 500);
        }
    }


    // Fetch updates
    // AK 2024-08-07: execution of this command stopped for unknown reason (solved by commenting out ob_start()/ob_end_flush()), but use exec_log(command, TRUE) to debug error stream.
    $fetch_result = exec_log("git --git-dir=\"$git_dir/.git\" fetch $CONFIG[remote_name]");
    if (0 !== $fetch_result) {
        print_log("Git Fetch failed with exit code $fetch_result.");
        if (128 === $fetch_result) {
            print_log("Exit code 128 usually means that security credentials are invalid. CHECK YOUR DEPLOYMENT KEY! Is it listed in ~/.ssh? Access granted for 'ssh_config'? Is the key prepared for user $current_user?");
        }
    }

    // ...We could PULL updates, but let's better do the "hard reset" to refresh EVERYTHING (if needed), not only updated stuff
    // $ret_val = exec_log("git --git-dir=\"$git_dir/.git\" --work-tree=\"$CONFIG[target_dir]\" pull $CONFIG[remote_name] $branch");
    // ...Do HARD RESET, to fully synchronize our deployment with Git...
    $ret_val = exec_log("git --git-dir=\"$git_dir/.git\" --work-tree=\"$CONFIG[target_dir]\" reset --hard $CONFIG[remote_name]/$branch");
    // Done
    print_log("'hard reset' finished with code $ret_val in ".number_format(microtime(1) - $start_time, 3).' seconds.'); // $ret_val 0 is good!


    // Switch to the correct branch for sure. It will respond something like "Already on 'master'" and this is fine.
    // UPD. We actually don't need this. We don't switch branches, so it's useless.
    //exec_log("git checkout $branch");
    // Also if we need to set up the branch to work with (could be useful after initial hard reset)
    //exec_log("git branch --set-upstream-to=$CONFIG[remote_name]/$branch $branch");


    // REMOVE DEPLOYED GARBAGE
    // =======================
    // chdir($CONFIG['target_dir']);
    // Consider 'git clean -fd' to remove untracked files.
    //
    // Delete directory
    exec_log("rm -rf $CONFIG[target_dir]/website/DIRECTORY_NAME");

    // Delete .htaccess in target_dir and all subdirectories. (We may use .htaccess in local environement, but don't need it on production Nginx droplet.)
    //exec_log("find $CONFIG[target_dir]/website/ -type f -name \".htaccess\" -exec rm -f {} \\;");
    // Delete README.md and possible .sql files.
    // exec_log("find $CONFIG[target_dir]/website/ \\( -name \"*.md\" -o -name \"*.sql\" \\) -type f -exec rm -f {} \\;");
    // Delete all Windows batch files AND backup files. Plus .src.js and .src.css.
    //exec_log("find $CONFIG[target_dir]/website/www/ \\( -name \"*.bat\" -o -name \"*.bak\" -o -name \"*.src.js\" -o -name \"*.src.css\" \\) -type f -exec rm -f {} \\;");

    /*
    function change_dir_permission(string $dir_name, string $file_ext, int $permission): void {
        // Make all .SH-files (except hidden) in /tools/ directory executable.
        if ($dir_handle = opendir($dir_name)) {
            try {
                while (false !== ($entry = readdir($dir_handle))) {
                    if ('.' === $entry[0]) { // skip all directories and system (hidden) files
                        continue;
                    }

                    if (is_dir($fn = $dir_name . DIRECTORY_SEPARATOR . $entry)) {
                        change_dir_permission($fn, $file_ext, $permission);

                    // Only if file has .sh extension
                    }elseif ($file_ext === pathinfo($entry, PATHINFO_EXTENSION)) {
                        $permission_str = sprintf('%04o', $permission); // dec to oct
                        // Update access privileges
                        print_log(chmod($fn, $permission)
                            ? "$permission_str privileges applied for $fn"
                            : "ERROR on setting $permission_str privileges for $fn");
                    }
                }
            }finally {
                closedir($dir_handle);
            }
        }else {
            print_log("Can't open $dir_name");
        }
    }
    change_dir_permission($CONFIG['target_dir'].'/tools', 'sh', 0755);
    */

    // Execute something to increase version in some environment variable
    //exec_log('php '.__DIR__."/inc_php_var.php $CONFIG[target_dir]/website/.env.php \\\$ext_script_ver v=")
    print_log('Cleared some garbage and increased version number.');

    print_log('Done in '.number_format(microtime(true) - $start_time, 3).' sec.', 200); // exit with "200 OK".

}finally {
    // get all stdout to write into log
    $out = ob_get_contents();
    ob_end_clean();
    echo $out;

    file_put_contents("$CONFIG[log_path]$log_name-stdout.log", $out);
}