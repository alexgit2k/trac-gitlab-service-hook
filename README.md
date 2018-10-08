Gitlab Service Hook Plugin for Trac
===================================

Adds git commit messages and merge requests as comments to trac tickets.
If a commit message or a merge request contains a trac ticket number like
`#123` this trac plugin will add it as a comment to the trac ticket.

The code is based on [githubservicehook](https://github.com/trac-hacks/githubservicehook/)
and tracopt/ticket/commit_updater.py of Trac.

## Install

Install the plugin into your trac project's plugins dir. To enable the plugin
add this to the bottom of your trac.ini file:

    [components]
    gitlabservicehook.* = enabled
    
    [gitlabservicehook]
    token = SECRET_TOKEN

Add a webhook in the gitlab project under Settings -> Integrations, where SECRET_TOKEN
is the same token as set in trac.ini. Supported triggers are "Push events" and/or
"Merge request events".

Finally, restart the web server that hosts your trac instance.
