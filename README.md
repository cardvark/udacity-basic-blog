# udacity-basic-blog
Basic Blog project for Udacity FSND intro to backend (unit 3)

Functioning hosted blog [link](http://jw-udacity-basic-blog.appspot.com/blog).

##Setup:

* Clone or [download](https://github.com/cardvark/udacity-basic-blog/archive/master.zip) the repo: `https://github.com/cardvark/udacity-basic-blog.git`
* Install [Google App Engine SDK](https://cloud.google.com/appengine/downloads#Google_App_Engine_SDK_for_Python) if necessary.

##Testing:

1. Open terminal to folder location of cloned repo.
2. Run page with command: `dev_appserver.py .`
3. Open browser to [http://localhost:8080/blog](http://localhost:8080/blog).

##Expected Functionality:
* Users can log in / log out.
* Logged in status remains for duration of browser session via cookie ID.
* Logged in users can create new blog posts.
* Logged in authors of blog posts can edit / delete posts.
* Logged in users can comment on existing posts.
* Logged in comment authors can edit / delete their own comments.
* Logged in users can Like / Unlike other user's blog posts.
* Edge case handling to protect against abusing above rules.
* Users cannot modify cookie ID to falsely log into another account.
  * passwords are hashed, salted, and peppered.
  * user cookie IDs are hashed and peppered.
