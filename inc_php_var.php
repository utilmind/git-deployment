<?php
#
# This script increase some variable in another PHP script.
# Internal, but feel free to modify it for your needs.
#
if (!is_array($argv) || ($i = count($argv)) < 3) {
    exit(<<<END
Usage: inc_php_var.php [filename.php] [\$var] [prefix (optionally, can be skipped)]
Example: inc_php_var.php .credentials.php \$ext_script_ver v=

END
    );
}

if ($content = file_get_contents($argv[1])) {

    $content = preg_replace_callback('/('.preg_quote($argv[2]).'\s*?=\s*?(\'|")'.preg_quote($argv[3] ?? '').')(.*?)(\'|")/s', function($m) {
               ++$m[3];
               return "$m[1]$m[3]$m[4]";
           }, $content);

    file_put_contents($argv[1], $content);
    echo "$argv[1] updated.\n";

}else {
    echo "$argv[1] not found.\n";
}
