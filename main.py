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
            self.render(
                newpost_page,
                blog_title=title,
                blog_content=content,
                error='Nice work!')
        else:
            error = 'Need both title and content'
            self.render(
                newpost_page,
                blog_title=title,
                blog_content=content,
                error=error)


class BlogMainHandler(Handler):
    def get(self):
        self.render(blog_post_page)


class MainHandler(Handler):
    def get(self):
        self.write("Hello Blog!")

app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/blog', BlogMainHandler),
    ('/blog/newpost', NewPostHandler)
], debug=True)
