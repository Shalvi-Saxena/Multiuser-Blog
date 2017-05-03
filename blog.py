"""BLOG PYTHON FILE"""


import os
import re
import random
import hashlib
import hmac

from string import letters

import webapp2
import jinja2
import datetime

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

secret = "udacity"

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

def blog_key(name='default'):
    return db.Key.from_path('blogs', name)

class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

class MainPage(BlogHandler):
    def get(self):
        self.render_front()

    def render_front(self, title="", content="", username="", error=""):
        try:
            posts = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC")
            
            if self.user:
                username = self.user.name
            if posts:
                for post in posts:
                    date = str(post.created)
                    date = datetime.datetime.strptime(date, '%Y-%m-%d %H:%M:%S.%f')
                    date = date.strftime("%d %b %Y")
                    post_id = post.key().id()
                self.render("index.html", username=username, posts=posts, date=date)
            else:
                self.render("index.html", date=date, username=username)
        except Exception:
            self.render("index.html", username=username)

def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group='default'):
    return db.Key.from_path('users', group)

class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(), name=name, pw_hash=pw_hash, email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

class Post(db.Model):
    title = db.StringProperty(required=True)
    image = db.StringProperty(required=False)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    username = db.StringProperty(required=True)
    comments = db.IntegerProperty()
    likes = db.IntegerProperty()

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        if self.user:
            return render_str("post.html", p=self, username=self.user.name)
        else:
            return render_str("post.html", p=self)

class Comment(db.Model):
    post_id = db.IntegerProperty(required=True)
    username = db.StringProperty(required=True)
    comment = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

class Like(db.Model):
    post_id = db.IntegerProperty(required=True)
    username = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if post:
            liked = False
            likeId = None
            try:
                comments = db.GqlQuery("SELECT * FROM Comment WHERE post_id ="
                                       +post_id+"ORDER BY created DESC LIMIT 20")
                likes = db.GqlQuery("SELECT * FROM Like WHERE post_id="+post_id)
                date = str(post.created)
                date = datetime.datetime.strptime(date, '%Y-%m-%d %H:%M:%S.%f')
                date = date.strftime("%d %b %Y")
            except Exception: 
              pass

            if self.user:
                for like in likes:
                    if self.user.name == like.username:
                        liked = True
                        likeId = like.key().id()
                        break
                self.render("post.html",
                            post=post,
                            likes=likes,
                            comments=comments,
                            username=self.user.name,
                            date=date,
                            liked=liked,
                            likeId=likeId
                            )
            else:
                self.render("post.html", post=post, comments=comments, date=date)
        else:
            return self.redirect('/')

class EditPost(BlogHandler):
    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if post:
            editTitle = self.request.get('editTitle')
            editImage = self.request.get('editImage')
            editContent = self.request.get('editContent')
            if editTitle and editContent and self.user:
                if post.username == self.user.name:
                    post.image = editImage
                    post.title = editTitle
                    post.content = editContent
                    post.put()                   
                    return self.redirect('/post/'+post_id)
            else:
                return self.redirect('/post/'+post_id)
        else:
            return self.redirect('/')

class DeletePost(BlogHandler):
    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if post:
            deletePost = self.request.get('deletePost')
            if deletePost and self.user:
                if post.username == self.user.name:
                    comments = Comment.all().filter('post_id =', int(post_id))
                    for comment in comments:
                        comment.delete()
                    post.delete()
                    return self.redirect('/post/'+post_id)
        else:
            return self.redirect('/')
            
class AddComment(BlogHandler):
    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if post:
            comment = self.request.get('content')

            if comment and self.user:
                c = Comment(parent=blog_key(),
                            comment=comment,
                            username=self.user.name,
                            post_id=int(post_id)
                            )
                c.put()
                if post.comments is None:
                    post.comments = 1
                else:
                    post.comments = int(post.comments) + 1;
                post.put()
                return self.redirect('/post/'+post_id)
            else:
                return self.redirect('/post/'+post_id)
        else:
            return self.redirect('/')

class EditComment(BlogHandler):
    def post(self,post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if post:
            commentId = self.request.get('commentId')
            editComment = self.request.get('editComment')
            if commentId and editComment and self.user:
                key = db.Key.from_path('Comment', int(commentId), parent=blog_key())
                comment = db.get(key)
                if comment:
                    if comment.username == self.user.name:
                        comment.comment = editComment
                        comment.put()
                        return self.redirect('/post/'+post_id)
                else:
                    return self.redirect('/post/'+post_id)
            else:
                return self.redirect('/')
        else:
            return self.redirect('/')

class DeleteComment(BlogHandler):
    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if post:
            commentId = self.request.get('commentId')
            c_key = db.Key.from_path('Comment', int(commentId), parent=blog_key())
            comment = db.get(c_key)
            if comment:    
                if commentId and self.user:
                    if comment.username:
                        comment.delete()
                        post.comments = int(post.comments) - 1
                        post.put()
                        return self.redirect('/post/'+post_id)
                    else:
                        return self.redirect('/post/'+post_id)
            else:
                return self.redirect('/')
        else:
            return self.redirect('/')

class LikePost(BlogHandler):
    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if post:
            likePost = self.request.get('likePost')
            liked = False
            likes = Like.all().filter('post_id =', int(post_id))
            if self.user:
                for like in likes:
                    if self.user.name == like.username:
                        liked = True
                        likeId = like.key().id()
                        break

            if likePost and self.user:
                if post.username != self.user.name and liked is False:
                    like = Like(parent=blog_key(), username=self.user.name, post_id=int(post_id))
                    like.put()
                    if post.likes is None:
                        post.likes = 1
                        post.put()
                        return self.redirect('/post/'+post_id)
                    else:
                        post.likes = int(post.likes) + 1
                        post.put()
                        return self.redirect('/post/'+post_id)
                else:
                    return self.redirect('/post/'+post_id)
        else:
            return self.redirect('/')

class UnlikePost(BlogHandler):
    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if post:
            unlikePost = self.request.get('unlikePost')
            liked = False
            likes = Like.all().filter('post_id =', int(post_id))
            if self.user:
                for like in likes:
                    if self.user.name == like.username:
                        liked = True
                        likeId = like.key().id()
                        break

            if unlikePost and self.user and liked is True:
                u_key = db.Key.from_path('Like', int(unlikePost), parent=blog_key())
                like = db.get(u_key)
                like.delete()
                post.likes = int(post.likes) - 1
                post.put()
                return self.redirect('/post/'+post_id)
            else:
                return self.redirect('/post/'+post_id)
        else:
            return self.redirect('/')
        
class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html", username=self.user.name)
        else:
            return self.redirect('/login')

    def post(self):
        if not self.user:
            return self.redirect('/login')

        title = self.request.get('title')
        image = self.request.get('image')
        content = self.request.get('content')
        username = self.user.name

        if title and content and self.user:
            p = Post(parent=blog_key(),
                     title=title,
                     image=image,
                     content=content,
                     username=username
                     )
            p.put()
            return self.redirect('/post/%s' % str(p.key().id()))
        else:
            error = "Title and content, please!"
            self.render("newpost.html",
                        title=title,
                        image=image,
                        content=content,
                        error=error,
                        username=username
                        )

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class SignUp(BlogHandler):
    def get(self):
        if self.user:
            return self.redirect('/')
        else:
            self.render("signup.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify_pass = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username, email=self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify_pass:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

class Register(SignUp):
    def done(self):
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            return self.redirect('/')

class Login(BlogHandler):
    def get(self):
        if self.user:
            return self.redirect('/')
        else:
            self.render('login.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        u = User.login(username, password)
        if u:
            self.login(u)
            return self.redirect('/')
        else:
            msg = 'Invalid login'
            self.render('login.html', error=msg)

class Logout(BlogHandler):
    def get(self):
        self.logout()
        return self.redirect('/')


class ShowUsers(BlogHandler):
    def get(self):
        users = db.GqlQuery("SELECT * FROM User LIMIT 10")
        if self.user:
            self.render('users.html', users=users, username=self.user.name)
        else:
            self.render('users.html', users=users)

app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/post/([0-9]+)', PostPage),
    ('/post/([0-9]+)/edit', EditPost),
    ('/post/([0-9]+)/delete', DeletePost),
    ('/post/([0-9]+)/addComment', AddComment),
    ('/post/([0-9]+)/editComment', EditComment),
    ('/post/([0-9]+)/deleteComment', DeleteComment),
    ('/post/([0-9]+)/like', LikePost),
    ('/post/([0-9]+)/unlike', UnlikePost),
    ('/newpost', NewPost),
    ('/signup', Register),
    ('/login', Login),
    ('/logout', Logout),
    ('/users', ShowUsers),
    ], debug=True)

