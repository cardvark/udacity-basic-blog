#!/usr/bin/env python

from datastores import *

import webapp2
import os
import jinja2
import re
import random
import string
import hmac
import hashlib
from google.appengine.ext import db

# Setting up jinja templates file path
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(template_dir),
    autoescape=True
    )

# regex requirements for user, password, email.
user_re = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
password_re = re.compile(r"^.{3,20}$")
email_re = re.compile(r"^[\S]+@[\S]+.[\S]+$")


# 'SECRET' to be added for cookie hashing.
# 'PEPPER' to add to salt for pw hashing.
SECRET = 'secretforcookies'
PEPPER = 'specialsecretpasswords'


# jinja templates, located in /templates
front_page = 'front.html'
blog_post_page = 'blog-post.html'
newpost_page = 'newpost.html'
thanks_page = 'thanks-post.html'
main_page = 'main-page.html'
signup_page = 'signup.html'
login_page = 'login.html'
edit_post_page = 'edit-post.html'
delete_post_page = 'delete-post.html'


class Blogs(db.Model):
    title = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    author = db.StringProperty(default='Anonymous')
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    @classmethod
    def blog_by_id(cls, blog_id):
        key = db.Key.from_path('Blogs', int(blog_id))
        blog = db.get(key)
        return blog

    def edit(self, title, content):
        self.title = title
        self.content = content
        self.put()

    @classmethod
    def delete_blog(cls, blog_id):
        key = db.Key.from_path('Blogs', int(blog_id))
        db.delete(key)


# need class methods to:
# - create Comments entity
# - edit comment
# - delete comment
class Comments(db.Model):
    blog_post = db.IntegerProperty(required=True)
    content = db.TextProperty(required=True)
    author = db.StringProperty(default='Anonymous')
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)


# User functions
def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()

    h = hashlib.sha256(PEPPER + name + pw + salt).hexdigest()
    return '{hash_out}|{salt}'.format(
        hash_out=h,
        salt=salt
        )

# creates random 5 letter string. Salt for hmac pw hashing
def make_salt():
    output_str = ''
    for i in range(5):
        output_str += random.choice(string.letters)

    return output_str

def valid_pw(name, pw, h):
    salt = h.split('|')[1]

    if h == make_pw_hash(name, pw, salt):
        return True


class Users(db.Model):
    user_name = db.StringProperty(required=True)
    pw = db.StringProperty(required=True)
    email = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add=True)

    @classmethod
    def entry_and_id(cls, user_name, password, email):
        pw = make_pw_hash(user_name, password)

        new_user = Users(
            user_name=user_name,
            pw=pw,
            email=email
            )
        new_user.put()
        return new_user.key().id()

    @classmethod
    def user_hashed_pw(cls, user_name):
        q = db.GqlQuery("""SELECT *
            from Users
            where user_name = '{name}'
            """.format(name=user_name))

        if q.get():
            return q.get().pw

    @classmethod
    def db_id_from_username(cls, user_name):
        q = db.GqlQuery("""SELECT __key__
            from Users
            where user_name = '{name}'
            """.format(name=user_name))
        if q.get():
            return q.get().id()


class CookieFunctions():
    # creates secure cookie string
    def make_cookie_id(self, s):
        return '{s}|{hash}'.format(s=s, hash=self.hash_str(s))

    # checks secure cookie string sent by user
    def check_cookie_id(self, cookie_id):
        if cookie_id:
            val = cookie_id.split('|')[0]
            if cookie_id == self.make_cookie_id(val):
                return val

    def give_cookie(self, db_id):
        db_id = self.make_cookie_id(str(db_id))
        self.response.headers.add_header(
            'set-cookie',
            'user_id={db_id}; Path=/'.format(db_id=db_id)
            )

    def username_from_cookie_id(self, cookie_id):
        if self.check_cookie_id(cookie_id):
            user = cookie_id.split('|')[0]
            key = db.Key.from_path('Users', int(user))
            return db.get(key).user_name

    def get_cookie_id(self):
        return self.request.cookies.get('user_id')

    # check validity of input based on regex reqs.
    def valid_reg_check(self, text_input, re_check):
        return re_check.match(text_input)

    # hashes string; for cookies.  Uses 'SECRET' to obfuscate.
    def hash_str(self, s):
        return hmac.new(SECRET, s).hexdigest()


class BlogBaseFunctions():
    def blog_redirect(self, blog_id):
        self.redirect('/blog/{blog_id}'.format(blog_id=str(blog_id)))

    def blog_author_check(self, blog, blog_id):
        if not blog:
            self.redirect('/blog')
        elif self.username != blog.author:
            self.blog_redirect(blog_id)


class Handler(webapp2.RequestHandler, CookieFunctions):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, logged_in, **params):
        t = jinja_env.get_template(template)
        params['logged_in'] = logged_in
        if self.username:
            params['username'] = self.username
        return t.render(params)

    def render(self, template, **kw):
        user_id = self.get_cookie_id()
        logged_in = True if user_id else False
        self.write(self.render_str(template, logged_in, **kw))

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        self.username = self.username_from_cookie_id(self.get_cookie_id())

    def check_user_redirect(self):
        if not self.username:
            self.redirect('/blog/signup')


class LogoutHandler(Handler):
    def get(self):
        self.response.headers.add_header(
            'set-cookie',
            'user_id=; Path=/'
            )
        self.redirect('/blog/signup')


class NewPostHandler(Handler, BlogBaseFunctions):
    def get(self):
        self.check_user_redirect()
        self.render(newpost_page)

    def post(self):
        title = self.request.get('subject')
        content = self.request.get('content')

        if title and content:
            # With proper submission, creates new blog entity for Blogs kind
            # Enters entity into Blogs
            # Then redirects user to the blog's specific page, using the blog's ID
            # ID generated by entry into the Blogs entity.
            new_blog = Blogs(
                title=title,
                content=content,
                author=self.username
                )
            new_blog.put()
            blog_id = new_blog.key().id()
            self.blog_redirect(blog_id)
        else:
            # If user tries to submit blog w/ out title and content
            # Receives the following error.
            # Use input is preserved in the fields.
            error = 'Need both title and content'
            self.render(
                newpost_page,
                blog_title=title,
                blog_content=content,
                error=error)


class ThanksPageHandler(Handler):
    def get(self):
        self.check_user_redirect()
        self.render(
            thanks_page,
            username=self.username,
            redirect_main=True
            )


class BlogMainHandler(Handler, BlogBaseFunctions):
    def get(self, blog_id=None):
        if blog_id:
            # Handles the /blog/#### case.
            # If digits passed in, checks if entity exists in database
            # Passes entity to blog_post_page template for a one-off page.
            blog = Blogs.blog_by_id(blog_id)
            if blog:
                time_diff = (blog.last_modified - blog.created).total_seconds()
                self.render(
                    blog_post_page,
                    blog=blog,
                    username=self.username,
                    time_diff=time_diff,
                    edit_url='/blog/{blog_id}/edit'.format(blog_id=blog_id)
                    )
            else:
                self.redirect('/blog')

        else:
            # if url is simply /blog, displays main_page
            # queries entire list of entities from Blogs
            # passes to main_page template, which will iterate over the list.
            # note - this isn't actually a list object, probably
            # not sure exactly what, should follow up.
            blogs = db.GqlQuery("""SELECT *
                from Blogs
                order by created desc
                limit 20
                """)

            self.render(main_page, blogs=blogs)

    def post(self, blog_id):
        pass


class EditPostHandler(Handler, BlogBaseFunctions):
    def get(self, blog_id):
        blog = Blogs.blog_by_id(blog_id)
        self.blog_author_check(blog, blog_id)

        self.render(
            edit_post_page,
            blog=blog,
            delete_url='/blog/{blog_id}/delete'.format(blog_id=str(blog_id))
            )

    def post(self, blog_id):
        title = self.request.get('subject')
        content = self.request.get('content')
        blog = Blogs.blog_by_id(blog_id)

        if title and content and self.username == blog.author:
            blog.edit(title, content)
            self.blog_redirect(blog_id)
        else:
            error = 'Need both title and content'
            self.render(
                edit_post_page,
                blog={'title': '', 'content': ''},
                blog_title=title,
                blog_content=content,
                error=error)


class DeletePostHandler(Handler, BlogBaseFunctions):
    def get(self, blog_id):
        blog = Blogs.blog_by_id(blog_id)
        self.blog_author_check(blog, blog_id)

        self.render(
            delete_post_page,
            blog=blog
            )

    def post(self, blog_id):
        blog = Blogs.blog_by_id(blog_id)
        self.blog_author_check(blog, blog_id)

        delete = self.request.get('delete')

        if delete == 'Yes':
            Blogs.delete_blog(blog_id)
            self.redirect('/blog')
        else:
            self.blog_redirect(blog_id)


class SignupHandler(Handler):
    def get(self):
        self.render(signup_page, username="")

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        password_verify = self.request.get('verify')
        email = self.request.get('email')

        valid_input = True

        params = {
            'username': username,
            'email': email
        }

        if Users.user_hashed_pw(username):
            params['username_error'] = "Username already taken."
            valid_input = False

        if not self.valid_reg_check(username, user_re):
            params['username_error'] = "Not a valid username."
            valid_input = False

        if not self.valid_reg_check(password, password_re):
            params['password_error'] = "Not a valid password."
            valid_input = False
        elif password != password_verify:
            params['password_mismatch'] = "Passwords didn't match."
            valid_input = False

        if email and not self.valid_reg_check(email, email_re):
            params['email_error'] = "Not a valid email"
            valid_input = False

        if username and password and password_verify and valid_input:
            db_id = Users.entry_and_id(username, password, email)
            self.give_cookie(db_id)
            self.redirect('/blog/welcome')
        else:
            self.render(
                signup_page,
                **params
                )


class LoginHandler(Handler):
    def get(self):
        self.render(login_page)

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        h = Users.user_hashed_pw(username)

        if h and valid_pw(username, password, h):
            user_id = Users.db_id_from_username(username)
            self.give_cookie(user_id)
            self.redirect('/blog/welcome')
        else:
            self.render(login_page, login_error='Invalid login information.')


class GqlHandler(Handler):
    def get(self):
        def write_blogs():
            blogs = db.GqlQuery("""SELECT *
                from Blogs
                order by created desc
                limit 20
                """)

            for blog in blogs:
                self.write(blog.key().id())
                self.write('<br>')

        write_blogs()

        # self.write(
        #     checkName('bobo')
        #     )

        # for item in q:
        #     self.write(item.pw)
        #     self.write('<br>')


class MainHandler(Handler):
    def get(self):
        self.redirect('/blog')


app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/blog', BlogMainHandler),
    ('/blog/newpost', NewPostHandler),
    ('/blog/welcome', ThanksPageHandler),
    ('/blog/signup', SignupHandler),
    ('/blog/login', LoginHandler),
    ('/blog/logout', LogoutHandler),
    # ('/blog/gqlhandler', GqlHandler),
    webapp2.Route(r'/blog/<blog_id:\d+>', BlogMainHandler),
    webapp2.Route(r'/blog/<blog_id:\d+>/edit', EditPostHandler),
    webapp2.Route(r'/blog/<blog_id:\d+>/delete', DeletePostHandler)
], debug=True)
