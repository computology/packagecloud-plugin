packagecloud.io Plugin
---------------------

Integrates packagecloud.io package repository hosting with Jenkins

Code & Bugs
-----------
See the Wiki page for links to github and bug tracker.

Installing
----------
You should install the packagecloud plugin from your Jenkins
Management console (look under available plugins)

Building
--------

$ mvn hpi:run

This will build the plugin, grab everything needed and start you up a
fresh Jenkins instance on a TCP/IP port for you to test against.

Releasing
---------

If you are the maintainer, you can simply:

$ mvn release:prepare release:perform


Maintainer
----------
Joe Damato <joe@packagecloud.io>
Julio Capote <julio@packagecloud.io>
