#!/usr/bin/env python

import random
import string
import hashlib
from google.appengine.ext import db

PEPPER = 'specialsecretpasswords'


class Blogs(db.Model):
    title = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    author = db.StringProperty(default='Anonymous')
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    @classmethod
    def entry_and_id(cls, title, content, user_name):
        new_blog = Blogs(
            title=title,
            content=content,
            author=user_name
            )
        new_blog.put()
        return new_blog.key().id()

    @classmethod
    def blog_by_id(cls, blog_id):
        key = db.Key.from_path('Blogs', int(blog_id))
        blog = db.get(key)
        return blog

    def edit(self, title, content):
        self.title = title
        self.content = content
        self.put()


class Comments(db.Model):
    blog_post = db.IntegerProperty(required=True)
    content = db.TextProperty(required=True)
    author = db.StringProperty(default='Anonymous')
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    @classmethod
    def entry_and_id(cls, blog_id, content, author):
        new_comment = Comments(
            blog_post=blog_id,
            content=content,
            author=author
            )
        new_comment.put()
        return new_comment.key().id()

    @classmethod
    def comment_by_id(cls, comment_id):
        key = db.Key.from_path('Blogs', int(comment_id))
        comment = db.get(key)
        return comment

    def edit(self, content):
        self.content = content
        self.put()

    @classmethod
    def delete_blog(cls, blog_id):
        key = db.Key.from_path('Blogs', int(blog_id))
        db.delete(key)

    @classmethod
    def get_comments(cls, blog_id, count):
        comments_list = db.GqlQuery("""SELECT *
            from Comments
            where blog_post = {blog_id}
            order by created desc
            limit {count}
            """.format(
            blog_id=blog_id,
            count=count
            )
        )

        return comments_list


# Need count method based on blog_id
# Need to check if author has or hasn't voted on the blog.
class BlogVotes(db.Model):
    author = db.StringProperty(required=True)
    blog_id = db.IntegerProperty(required=True)
    vote = db.IntegerProperty(default=1)

    @classmethod
    def vote_entry(cls, author, blog_id):
        new_vote = BlogVotes(
            author=author,
            blog_id=blog_id
            )

        new_vote.put()
        return new_vote.key().id()

    # @classmethod
    # def vote_count(cls, blog_id):
    #     votes = BlogVotes.all()
    #     votes.filter("blog_id =", blog_id)

    #     count_val = 0

    #     for item in votes:
    #         count_val += item.vote

    #     return count_val

    # @classmethod
    # def speak_up(cls):
    #     print "whoof"

    @classmethod
    def vote_count(cls, blog_id):
        count_list = db.GqlQuery("""SELECT *
            from BlogVotes
            where blog_id = {blog_id}
            """.format(
            blog_id=blog_id
            )
        )

        count_val = 0

        for item in count_list:
            count_val += item.vote

        return count_val


# User functions
def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()

    h = hashlib.sha256(PEPPER + name + pw + salt).hexdigest()
    return '{hash_out}|{salt}'.format(
        hash_out=h,
        salt=salt
        )


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

    @classmethod
    def login_check(cls, user_name, password):
        h = Users.user_hashed_pw(user_name)

        if h and valid_pw(user_name, password, h):
            return True
