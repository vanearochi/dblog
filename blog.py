import os
import webapp2
import jinja2
from webapp2 import RequestHandler
from google.appengine.ext import db
import random
import string
import hashlib

path_template_dir = os.path.join(os.path.dirname(__file__), "templates")
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(path_template_dir), autoescape=True)


class Blog(db.Model):
    title = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)


class User(db.Model):
    user_name = db.StringProperty(required=True)
    user_password = db.StringListProperty(required=True)
    user_email = db.EmailProperty(required=False)


class Handler(RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))


class NewPost(Handler):
    def get(self):
        # type: () -> object
        template_name = "blog_entry.html"
        self.render(template_name, title="", content="")

    def check_entry(self, entry_name, entry):
        min_length_required = 0
        entry_length = len(entry)
        error1_response = "Please add a"
        error2_response = "Please enter a minimum of"
        if entry_name == "title":
            min_length_required = 2
        else:
            min_length_required = 1

        if len(entry) == 0:
            return error1_response + " " + entry_name
        elif len(entry) < min_length_required:
            return error2_response + " " + str(min_length_required) + " " + entry_name
        else:
            return True

    def post(self):
        template_error = "blog_entry.html"
        blog_title = self.request.get("title")
        blog_content = self.request.get("content")
        title_status = self.check_entry("title", blog_title)
        content_status = self.check_entry("content", blog_content)

        if title_status == True and content_status == True:
            new_database_entry = Blog(title=blog_title, content=blog_content)
            new_database_entry.put()
            cursor_rows = db.GqlQuery("SELECT * FROM Blog")
            # print new_database_entry.key().id()
            id_created = new_database_entry.key().id()
            self.redirect_to("newcreatedpost", blog_id=id_created)
            # elif title_status != True and content_status != True:
            #     user_error = title_status + ". " + content_status
            #     self.render(template_error, error=user_error)
            # elif title_status:
            #     self.render(template_error, error=content_status)
            # else:
            #     self.render(template_error, error=title_status)


class BlogPosts(Handler):
    def get(self):
        # type: () -> object
        template_name = "blog_posts.html"
        posts = db.GqlQuery("SELECT * FROM Blog order by created desc limit 10")
        self.render(template_name, posts=posts)


#
class SinglePost(Handler):
    def get(self, blog_id):
        key = db.Key.from_path("Blog", int(blog_id))
        # print key
        post = db.get(key)
        self.render("blog_redirect.html", post=post)


class SignUp(Handler):
    def get(self):
        self.render("blog_signup.html", user_name="", user_password="", user_email="")

    def post(self):
        dir = {}
        name = self.request.get("userName")
        name_status = self.name_validator(name)
        # name_database_status = self.is_in_database(name)
        password = self.request.get("userPassword")
        password_confirmation = self.request.get("passwordConfirmation")
        password_status = self.password_validator(password, password_confirmation)
        email = self.request.get("userEmail")
        self.email_validator(email)
        status_result = []
        email_status = ""
        a = self.hash_it_with_salt("vane", "hola")
        print a
        # rint status_result
        if len(email) > 0 and email.isspace() != True:
            email_status = self.email_validator(email)
            status_result.append(name_status)
            status_result.append(password_status)
            status_result.append(email_status)
            # print status_result
            # print all(result == True for result in status_result)
            if all(result == True for result in status_result):
                self.save_in_db(name, password, email)
                # self.response.headers.add_header("Set-Cookie", user)
                self.redirect_to("NewPost")
            else:
                # print "yay2"
                self.render("blog_signup.html", user_name=name, user_password="", user_email=email,
                            name_status=name_status, password_status=password_status, email_status=email_status)
        else:
            status_result.append(name_status)
            status_result.append(password_status)
            if all(result == True for result in status_result):
                self.save_in_db(name, password)
                self.redirect("NewPost")
            else:
                self.render("blog_signup.html", user_name=name, user_password="", user_email="",
                            name_status=name_status, password_status=password_status, email_status=email_status)

    def name_validator(self, userName):
        # Check if the user's name has a proper length
        # TODO: Use Regex to check alphanumeric and length

        error_name = "Please enter a valid name"
        if all(result != " " for result in userName):
            if 3 < len(userName) < 25:
                return self.is_in_database(userName)
            else:
                return error_name
        else:
            return error_name

    def is_in_database(self, userName):
        ##Check if user name is in database already
        # q = User.all()
        q = User.all()
        q.filter("user_name =", userName)
        print
        print q

        # q.execute("select user_name from User")


        # key = db.Key.from_path("Blog", int(blog_id))
        # print key


        # a = q.filter('__user_name__ =', userName)
        # print a.key
        # print query.name

        error_name_database = "This name is already in use, please enter a new one"

        # username = query.filter("user_name =", userName)
        # print username
        va = q.get()
        # print va


        if va == None:
            return True
        else:
            return error_name_database

            # new_userdatabase_entry = User(user_name=blog_title, user_password=blog_content, user_email=)
            # new_userdatabase_entry.put()

    def password_validator(self, userPassword, passwordConfirmation):
        status = []
        error_valid_password = "Please enter a valid password"
        error_match_password = "Passowords entered don't match"

        if all(result != " " for result in userPassword):
            if 6 < len(userPassword) < 20:
                if userPassword == passwordConfirmation:
                    return True
                else:
                    return error_match_password

        return error_valid_password

    def email_validator(self, email):

        error_valid_email = "Please enter a valid email"
        regex_email = "[a-zA-Z1-9@]"

        # bla = email.find(' ')
        # blo = email.find("@")
        # blu = email[-4:]
        # print bla
        # print blo
        # print blu
        if email.find(' ') == -1 and email.find("@") != -1:
            if email[-4:] == ".com":
                return True

        return error_valid_email
        status = []

        ##if mail finish

    def save_in_db(self, userName, userPassword, email=None):
        # type: (object, object, object) -> object
        userEmail = email
        encrypt_password = self.hash_it_with_salt(userName, userPassword)
        new_database_entry = User(user_name=userName, user_password=encrypt_password, user_email=userEmail)
        new_database_entry.put()

    def hash_it_with_salt(self, name, password):
        # type: (object, object) -> object
        ##With a lil help from stackoverflow: http://stackoverflow.com/questions/2257441/random-string-generation-with-upper-case-letters-and-digits-in-python/23728630#23728630
        salt = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for x in xrange(10))
        hash = hashlib.sha512(name + password + salt).hexdigest()

        print hash
        print salt
        return [hash, salt]


class LogIn(Handler):
    def get(self):
        template_name = "blog_login.html"
        self.render(template_name)

    def post(self):
        user_name = self.request.get("name")
        user_password = self.request.get("password")

        #if all(result != " " for result in user_name) and all(result != " " for result in user_password):
        if all(result != " " for result in user_name):
            print "hola"
            self.get_from_db(user_name)

        else:
            print "a"
            "Please print a valid Username/Password"


        #print b
        #print user_name
        #print user_password

    def get_from_db(self, userName):

        q = User.all()
        #q.filter("user_name =", userName)
        #print q.index_list()
        #print q.fetch(1)
        q.filter("user_name =", userName)
        match = q.fetch()
        print match
        error_db = "This Username doesn't exist in our db"

        if match == None:
            #print match
            return error_db
        else:
            print error_db
            #return match






app = webapp2.WSGIApplication([webapp2.Route('/', handler=Handler, name='home'),
                               webapp2.Route('/blog/blogposts', handler=BlogPosts, name='Posts'),
                               webapp2.Route('/blog/newpost', handler=NewPost, name='NewPost'),
                               webapp2.Route(r'/blog/<blog_id:[0-9]+>', handler=SinglePost, name='newcreatedpost'),
                               webapp2.Route('/blog/signup', handler=SignUp, name='signup'),
                               webapp2.Route('/blog/login', handler=LogIn, name='Login'),],
                               debug=True)

# app = webapp2.WSGIApplication([('/', Handler), ('/blog', BlogPosts), ('/blog/newpost', NewPost), ], debug=True)
