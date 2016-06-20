Webhook
========================
This is a webhook app meant to handle webhook calls from the various items
across the crops organization.

POST Headers
---------------------
  Each POST is expected to have the following headers.

* **X-Github-Event**

  The *event* calling the webhook is expected to be in an http header
  *X-GitHub-Event*.

* **X-Hub-Signature**

  Authorization is handled by an http header identified by *X-Hub-Signature*.
  This header is the hmac digest of the payload created using a secret key and
  sha1. The digest will always be prefixed with *sha1=*.

  For example, the digest could be created using the following call to openssl:
  ```
  echo -n "somedata" | openssl sha1 -hmac secretkey
  ```
  And then *sha1=* would be prefixed. A full signature may look like:
  ```
  sha1=5a2985bd0a3e4e35691add40bb16943749f576b7
  ```

Configuration
---------------------
* **Default**
  The default configuration consists of the following values:
  ```
  HANDLERS_FILE = '/etc/crops-webhook/handlers.cfg'
  KEY_FILE = '/etc/crops-webhook/key'
  ROUTE = '/webhook'
  ```
  Any of these values can be overridden in a file specified in the
  *CROPS_WEBHOOK_CONFIG* environment variable.

   * **HANDLERS_FILE**

     This specifies the file containing information on what script to call for
     each handler. It's format is described in the *Event Handlers* section.

   * **KEY_FILE**

     This file contains the key used to generated the hmac digest for the
     payload. The key can also be specified using the *CROPS_WEBHOOK_KEY*
     environment variable.

   * **ROUTE**

     The route is the portion of the url that will come after where your
     webapp is hosted. For instance if we were hosting on localhost, and the
     *route* was set to *myroute*:
     ```
     http://localhost/myroute
     ```

Event Handlers
---------------------
  * **HANDLERS_FILE format**

    When the webhook is called, the app will check *HANDLERS_FILE* to determine
    what to call for the event. It is expected the file will have a *Handlers*
    section followed by event/handler pairs for each event that should be
    handled.

    The *handler* can either be an absolute path, or it can be a path that is
    relative to the *HANDLERS_FILE*.

    This is an example configuration file:
    ```
    [Handlers]
    event=/somepath/somescript.sh
    anotherevent=relativepath/someotherapp.py
    ```

    For an example, assume that ```HANDLERS_FILE=/handlers/handlers.cfg```.
    Using the example handlers.cfg above, the directory layout would be:
    ```
    .
    ├── handlers
    │   ├── handlers.cfg
    │   └── relativepath
    │       └── sometotherapp.py
    └── somepath
        └── somescript.sh
    ```

  * **Handler API**
    * **Inputs**

      A *handler* can be any type of executable file. When the *handler* is
      executed, it will be passed a directory name. If there was a payload with
      the event, the payload will be in a file called **payload**.

      In other words, if the handler was called *myhandler.sh*, it would be like
      running the following command from the shell.
      ```
      myhandler.sh /somedir
      ```
      And if there was a payload received, the directory layout would look
      like:
      ```
      .
      └── somedir
          └── payload
      ```
    * **Output**

      If a *handler* needs to send a *response* other than the default, the
      *handler* can create a file called **response** for this purpose.

      Once again, lets assume the directory passed to the handler was
      *somedir*. Then to send a response, before exiting the handler, the
      handler would create a file called **response**. That would create a
      directory layout:
      ```
      .
      └── somedir
          └── response
      ```

  * **Example handler**

    Here is a very simple handler in shell script. The handler will check for
    some data in the payload and respond differently based on the payload.
    ```bash
    #!/bin/bash
    
    # Get the directory containing the payload
    workdir=$1
    
    # Get the payload
    payload=$workdir/payload
    
    # Set the location of response
    response=$workdir/response
    
    if grep "expected data" $workdir/payload; then
        echo -n "Got expected data" > $workdir/response
    else
        echo -n "Didn't get expected data" > $workdir/response
    fi
    ```
