Webhook
========================
This is a webhook app meant to handle webhook calls from the various items
across the crops organization.

Basic design
---------------------
* **Identification**

  The *event* calling the webhook is expected to be in an http header
  *X-CROPS-Event*.

* **Authorization**

  Authorization is handled by an http header identified by *X-CROPS-Auth*.
  This header is the hmac digest of the payload and using a secret token as
  the key.

  For example, the digest could be created using the following call to openssl:
  ```
  echo -n "somedata" | openssl sha1 -hmac secretkey
  ```

Running the app
---------------------
* **Auth key**

  The *key* used to generate the digest of incomming payloads should be set
  in the *WEBHOOK_SECRET_TOKEN* environment variable.

* **Handlers**

  When the webhook is called, the app will check a handlers file for the app
  to call for the even. It is expected the file will have a *Handlers* section
  followed by event/handler pairs for each event that should be handled.

  This is an example configuration file:
  ```
  [Handlers]
  event=/somepath/somescript
  anotherevent=/someotherpath/someotherapp
  ```
