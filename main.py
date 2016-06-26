#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2
import os
import jinja2
import time

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(template_dir),
    autoescape=True
    )

front_page = 'front.html'
blog_post_page = 'blog-post.html'
newpost_page = 'newpost.html'
thanks_page = 'thanks-post.html'


class Blogs(db.Model):
    title = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)


class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))


class NewPostHandler(Handler):
    def get(self):
        self.render(newpost_page)

    def post(self):
        title = self.request.get('blog-title')
        content = self.request.get('blog-content')

        if title and content:
            new_blog = Blogs(title=title, content=content)
            new_blog.put()
            blog_id = new_blog.key().id()
            print blog_id
            self.redirect('/blog/thanks')
        else:
            error = 'Need both title and content'
            self.render(
                newpost_page,
                blog_title=title,
                blog_content=content,
                error=error)


class ThanksPageHandler(Handler):
    def get(self):
        self.render(thanks_page, redirect_main=True)
        # time.sleep(5)
        # self.redirect('/blog')


class BlogMainHandler(Handler):
    def get(self, blog_id=None):
        if blog_id:
            self.write("whoa! " + blog_id)
        else:
            self.render(blog_post_page)


class MainHandler(Handler):
    def get(self):
        self.write("Hello Blog!")


app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/blog', BlogMainHandler),
    ('/blog/newpost', NewPostHandler),
    ('/blog/thanks', ThanksPageHandler),
    webapp2.Route(r'/blog/<blog_id:\d+>', BlogMainHandler)
], debug=True)
