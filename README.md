# git-deployment and code-integrity-checker

Git deployment (and monitoring the code integrity) examples by UtilMind

#### QUICK START:
1. Rename this PHP-script into your project name
2. Modify the configuration options below ($CONFIG), according to your environment. (Don't forget to specify unique 'secret'. Use the same secret passphrase for your Git Webhook.)
3. Upload this script to your serer and point the URL to this script as WebHook.

If you did everything right, your web project will be automatically updated from Git on every `git push`. All files and directory structure on your web server will be synchronized with the content in Git repository. Everything will be mirrored, everything what supposed to be deleted will be deleted.

The good practice is to use code integrity checker, to monitor the code and inform administrator about all possible modifications outside of the Git repository (inform about possible malicious code injections, hacks). Use `code-integrity-checker.php` as example to monitor your live code.

#### IMPORTANT!
* <b>You never need `sudo` to pull updates from Git.</b> If you think that you need to be a sudoer to use this script – you’re doing something wrong. The web user should _NEVER_ have a super-privileges. Otherwise your web app is critically vulnerable.
* Do not accidentally publish `/.git` directory. Keep it outside of any `public_html`’s.

#### CONTRIBUTORS to original branch:
* Please keep legacy PHP5 syntax;
* Don't require any other libraries. Use only standard PHP5 functions.

#### MISCELLANEOUS TIPS:
* How to create Deploy key: https://docs.github.com/en/authentication/connecting-to-github-with-ssh/managing-deploy-keys#deploy-keys
  Briefly...
  
  1. Generate key:
    ```
      ssh-keygen -t ed25519 -C "<email@address>" -f <key_file_name>
    ```
  2. Add key to ssh-agent:
    ```
      `eval "$(ssh-agent -s)"
      ssh-add ~/.ssh/<key_file_name>`
    ```
  3. Open /etc/ssh/ssh_config (or create new file in "/etc/ssh/ssh_config/ssh_config.d/" if your ssh_config including files in "ssh_config.d" directory, or use local config "~/.ssh/config")
  Add some record like follows:
    ```
    Host <git_hostname, eg. github.com or bitbucket.org>-<your_repository_name>
      HostName <git_hostname, eg. github.com or bitbucket.org>
      IdentityFile ~/.ssh/<key_file_name>
      IdentitiesOnly yes
    ```
