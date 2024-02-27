<?php
/**
    Code integrity checker example by UtilMind.

    @see       https://github.com/utilmind/git-deployment/ The GitHub project
    @author    Oleksii Kuznietsov (utilmind) <utilmind@gmail.com>

    USAGE:
        * This script can be used to check code integrity (comparing it with original Git repository)
          and inform Administrator about any code modifications, injections, hacks.

        * This script supposed to run on crontab, several times per hour. (The more often is better.)

        * Script accepts paths as command-line arguments. Run it as follows:
              php code-integity-checker.php [path to .git directory] [your project code directory] [site name (optional)]

        * Don't mix this integrity checker with your primary project code. Better rename it and hide somewhere.

    CONTRIBUTORS to original branch:
        * Please keep legacy PHP5 syntax;
        * Don't require any other libraries. Use only standard PHP5 functions.
**/

// gettings arguments
if (!is_array($argv) || count($argv) < 3) {
    echo <<<END
Usage: $argv[0] [git directory] [project code directory] [sitename (optional)]

END;
    exit;
}

function add_trailing_slash($d) {
    return $d.((substr($d, -1) === '/') ? '' : '/');
} // * remove trailing slash with: rtrim($str, '/');


$git_dir = add_trailing_slash($argv[1]).'.git'; // add '/.git' to provided path
$target_dir = add_trailing_slash($argv[2]);
$sitename = empty($argv[3]) ? basename($target_dir) : $argv[3];


// ideas: https://stackoverflow.com/questions/5237605/how-to-run-git-status-and-just-get-the-filenames
// documentation: https://git-scm.com/docs/git-ls-files
// See also: git fsck --full (check integrity of git folder itself: https://stackoverflow.com/questions/42479034/how-to-verify-integrity-of-a-git-folder)
//
if (exec("git --git-dir=\"$git_dir\" --work-tree=\"$target_dir\" ls-files -md", $output, $ret)) { // md = modified + deleted
    if (0 !== $ret) {
        echo "Return code: $ret\n";

    }else {
        // collect information about changes that occurred without using a Git repository
        $out = '';
        foreach ($output as $file) {
            $fn = $target_dir.$file; // changed file name

            $line = $fn.' - '.date('Y-m-d H:i:s', filemtime($fn))."\n";
            echo $line; // output into console as plain text too

            $out.= '<li>'.$line.'</li>'; // modify this if you don't like HTML
        }

        $last_check_fn = __DIR__.'/status/'.basename($argv[0]).'-'.$sitename.'-last.log';
        if (@file_get_contents($last_check_fn) !== $out) {
            file_put_contents($last_check_fn, $out);

            // --------------------------------------------------
            // send notifications to Admin emails and messengers!
            // --------------------------------------------------
        }
    }
}
