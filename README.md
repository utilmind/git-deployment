# git-deployment

UtilMind Git deployment script example.

#### QUICK START:
1. Rename this script into your project name
2. Modify the configuration options below ($CONFIG), according to your environment. (Don't forget to specify unique 'secret'.)
3. Upload this script to your serer and point the URL to this script as WebHook.

#### IMPORTANT!
You never need sudoer privileges when executing this script. <b>You never need `sudo` to pull updates from Git.</b>
If you think that you need it – you’re doing something wrong. Anyway, the web user should _NEVER_ have a super-privileges. Otherwise your web app is critically vulnerable.

#### CONTRIBUTORS to original branch:
* Please keep legacy PHP5 syntax;
* Don't require any other libraries. Use only standard PHP5 functions.
