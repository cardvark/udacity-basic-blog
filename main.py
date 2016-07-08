#!/usr/bin/env python

from datastores import *

import webapp2
import os
import jinja2
import re
import hmac
import time
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
SECRET = 'secretforcookies'


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


# Generation, validation, and other cookie ID functions.
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


class ThanksPageHandler(Handler):
    def get(self):
        self.check_user_redirect()
        self.render(
            thanks_page,
            username=self.username,
            redirect_main=True
            )


# Some blog post management specific functions
class BlogBaseFunctions():
    def blog_redirect(self, blog_id):
        self.redirect('/blog/{blog_id}'.format(blog_id=str(blog_id)))

    def blog_author_check(self, blog, blog_id):
        if not blog:
            self.redirect('/blog')
        elif self.username != blog.author:
            self.blog_redirect(blog_id)


class BlogMainHandler(Handler, BlogBaseFunctions):

    def build_vote_dict(self, blog_iterable):
        vote_dict = {}

        for blog in blog_iterable:
            blog_id = blog.key().id()
            liked = BlogVotes.vote_check(self.username, blog_id).get()

            vote_dict[blog.key().id()] = [
                BlogVotes.vote_count(blog_id),
                liked
            ]

        return vote_dict

    def get_all_blogs_page(self, like_error=None):
        # if url is simply /blog, displays main_page
        # queries entire list of entities from Blogs
        # passes to main_page template, which will iterate over the list.

        blogs = Blogs.get_blogs(20)

        vote_dict = self.build_vote_dict(blogs)

        self.render(
            main_page,
            blogs=blogs,
            vote_dict=vote_dict,
            like_error=like_error
        )

    def get_single_blog_page(self, blog_id):
        blog = Blogs.blog_by_id(blog_id)
        comments_list = Comments.get_comments(int(blog_id), 20)

        # handles case of incorrect blog_id in url.
        if not blog:
            self.redirect('/blog')
            return

        # put [blog] into a list to work with build_vote_dict
        vote_dict = self.build_vote_dict([blog])

        time_diff = (blog.last_modified - blog.created).total_seconds()
        self.render(
            blog_post_page,
            blog=blog,
            vote_dict=vote_dict,
            comments_list=comments_list,
            time_diff=time_diff,
            edit_url='/blog/{blog_id}/edit'.format(blog_id=blog_id)
            )

    def get(self, blog_id=None):
        if blog_id:
            # Handles the /blog/#### case.
            # If digits passed in, checks if entity exists in database
            # Passes entity to blog_post_page template for a one-off page.
            self.get_single_blog_page(blog_id)
        else:
            self.get_all_blogs_page()

    # Only comments need post handling right now.
    # therefore, assumption is that this is a specific blog page.
    def post(self, blog_id=None):
        if blog_id:
            blog = Blogs.blog_by_id(blog_id)
        else:
            blog = None

        like_error = None
        like = self.request.get('like')
        unlike = self.request.get('unlike')
        comment_submit = self.request.get('comment-submit')

        if like:
            like_error = []
            like_error.append(int(like))
            vote = BlogVotes.vote_check(self.username, int(like))
            if vote.get():
                like_error.append("Can't vote more than once!")
            elif self.username != Blogs.blog_by_id(like).author:
                BlogVotes.vote_entry(self.username, int(like))
                time.sleep(1)
            else:
                like_error.append("Can't vote on your own post!")
        elif unlike:
            vote = BlogVotes.vote_check(self.username, int(unlike))
            vote.get().delete()
            time.sleep(1)

        if not blog:
            self.get_all_blogs_page(like_error)
            return

        vote_dict = self.build_vote_dict([blog])
        comments_list = Comments.get_comments(int(blog_id), 20)
        content = self.request.get('comment-content')
        valid_comment = True

        error = ''

        if comment_submit:
            if not self.username:
                error = 'Must be logged in to comment'
                valid_comment = False
            elif not content:
                error = 'Must enter some text'
                valid_comment = False

            if valid_comment:
                Comments.entry_and_id(
                    int(blog_id),
                    content,
                    self.username
                    )
                time.sleep(1)

        time_diff = (blog.last_modified - blog.created).total_seconds()
        self.render(
            blog_post_page,
            blog=blog,
            vote_dict=vote_dict,
            time_diff=time_diff,
            comments_list=comments_list,
            edit_url='/blog/{blog_id}/edit'.format(blog_id=blog_id),
            like_error=like_error,
            error=error
            )


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
            blog_id = Blogs.entry_and_id(
                title,
                content,
                self.username
                )
            # Note - added a 1 second sleep delay
            # to allow time for datastore to update.
            time.sleep(1)
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
            blog.delete()
            self.redirect('/blog')
        else:
            self.blog_redirect(blog_id)


class SignupHandler(Handler):
    def get(self):
        self.render(signup_page)

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

        if Users.login_check(username, password):
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
