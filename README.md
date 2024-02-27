# git-deployment

Git deployment (and monitoring the code integrity) examples by UtilMind

#### QUICK START:
1. Rename this PHP-script into your project name
2. Modify the configuration options below ($CONFIG), according to your environment. (Don't forget to specify unique 'secret'.)
3. Upload this script to your serer and point the URL to this script as WebHook.

If you did everything right, your web project will be automatically updated from Git on every `git push`. All files and directory structure on your web server will be synchronized with the content in Git repository. Everything will be mirrored, everything what supposed to be deleted will be deleted.

The good practice is to use code integrity checker, to monitor the code and inform administrator about all possible modifications outside of the Git repository (inform about possible malicious code injections, hacks). Use `code-integrity-checker.php` as example to monitor your live code.

#### IMPORTANT!
* You never need sudoer privileges when executing this script. <b>You never need `sudo` to pull updates from Git.</b>
If you think that you need it – you’re doing something wrong. Anyway, the web user should _NEVER_ have a super-privileges. Otherwise your web app is critically vulnerable.
* Do not accidentally publish `/.git` directory. Keep it outside of any `public_html`’s.

#### CONTRIBUTORS to original branch:
* Please keep legacy PHP5 syntax;
* Don't require any other libraries. Use only standard PHP5 functions.
