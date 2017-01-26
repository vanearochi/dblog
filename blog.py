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
    user_name = db.StringProperty(required=True)
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


    def get_hash_with_salt(self, name, password, salt):
        user_hash = hashlib.sha512(name + password + salt).hexdigest()
        return user_hash

    def get_key(self, user_name):
        query = User.all(keys_only=True)

        user_key_query = query.filter("user_name =", user_name)
        user_key = user_key_query.get()
        return user_key

    def cookie_checker(self, cookie_name):
        split_cookie_value = cookie_name.split("|")
        hash_value = split_cookie_value[1]
        user_name = split_cookie_value[0]
        #print user_name
        db_user_key = self.get_key(user_name)
        hash_status = self.hash_validator(hash_value, db_user_key)
        if hash_status is True:
            return user_name
        else:
            return hash_status


    def hash_validator(self, hash_value, user_key):

        #print user_key
        user_entity = User.get(user_key)
        user_password = user_entity.user_password
        if user_password[0] == hash_value:
            #print "sip"
            return True
        else:
            return False


    def get_from_db(self, user_name):

        q = User.all()
        #print q
        ##print a.get()
        #b = a.get()
        #print b
        # get entity:
        #key = db.get(b)
        #c = key.user_password
        #print c
        #print db.k
        #q.filter("user_name =", userName)
        #print q.index_list()
        #print q.fetch(1)
        match = ""
        error_db = "This Username doesn't exist in our db"
        if match == None:
            #print match
            return error_db
        else:
            print error_db
            #return match

    def check_entry(self, entry_name, entry):
        min_length_required = 0
        entry_without_spaces = entry.replace(" ", "")
        #print entry_without_spaces
        error1_response = "Please add a"
        error2_response = "Please enter a minimum of"
        if entry_name == "title":
            min_length_required = 2
        else:
            min_length_required = 1

        if len(entry_without_spaces) == 0:
            return error1_response + " " + entry_name
        elif len(entry_without_spaces) < min_length_required:
            return error2_response + " " + str(min_length_required) + " " + entry_name
        else:
            return True


class SignUp(Handler):
    def get(self):
        self.render("blog_signup.html", user_name="", user_password="", user_email="", current_page="signUp")

    def post(self):

        if self.request.POST.get("loginPage"):
            self.redirect_to("Login")
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
        #print a
        # rint status_result
        if len(email) > 0 and email.isspace() is not True:
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
                            name_status=name_status, password_status=password_status, email_status=email_status, current_page="signUp")
        else:
            status_result.append(name_status)
            status_result.append(password_status)
            if all(result == True for result in status_result):
                self.save_in_db(name, password)
                self.redirect("NewPost")
            else:
                self.render("blog_signup.html", user_name=name, user_password="", user_email="",
                            name_status=name_status, password_status=password_status, email_status=email_status, current_page="signUp" )

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
        q = User.all(keys_only=True)
        q.filter("user_name =", userName)

        #print q

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
        User_instance = new_database_entry.put()
        hash = encrypt_password[0]
        self.set_cookie(hash, userName)


    def hash_it_with_salt(self, name, password):
        # type: (object, object) -> object
        ##With a lil help from stackoverflow: http://stackoverflow.com/questions/2257441/random-string-generation-with-upper-case-letters-and-digits-in-python/23728630#23728630
        salt = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for x in xrange(10))
        hash = hashlib.sha512(name + password + salt).hexdigest()

        #print hash
        #print salt
        return [hash, salt]

    def set_cookie(self, hash, userName):
        value = userName + "|" + hash
        self.response.set_cookie("name", value)

class LogIn(Handler):
    def get(self):
        cookie_value = self.request.cookies.get("name")
        #print cookie_value
        if cookie_value is not None:
            valid_cookie = self.cookie_checker(cookie_value)
            if valid_cookie is not False:
                self.redirect_to("Welcome")
            else:
                self.redirect_to("Login")

        template_name = "blog_login.html"
        self.render(template_name, current_page="login")
        cookie_val = self.request.cookies.get("name")

    def post(self):
        user_name = self.request.get("name")
        ##http://stackoverflow.com/questions/21505255/identify-which-submit-button-was-clicked-in-django-form-submit
        if self.request.POST.get("signUpPage"):
            #print user_name
            self.redirect_to("SignUp")
        user_password = self.request.get("password")
        cookie_value = self.request.cookies.get("name")
        if cookie_value is not None:
            valid_cookie = self.cookie_checker(cookie_value)
            #print "post"
            ##add verify name
        # else:
        #     split_cookie_value = cookie_value.split("|")
        #     salt_value = split_cookie_value[1]
        #     hash_value = self.get_hash_with_salt(user_name, user_password, salt_value)
        #     if split_cookie_value[0] == hash_value:
        #         self.redirect_to("NewPost")
        #     else:
        #         valid_name= self.verify_name(user_name)

    def verify_name(self, user_name):
        #if all(result != " " for result in user_name) and all(result != " " for result in user_password):
        if all(result != " " for result in user_name):
            #print "hola"
            name_in_db = self.get_from_db(user_name)
            if name_in_db == None:
                "This username is not registered"
                ##check_password = get_hash_with_salt(user_name, user_password, salt_value)
            else:
                self.get_key()
                check_password = get_hash_with_salt(user_name, user_password, cookie_value)
        else:
            #print "a"
            "Please enter a valid Username/Password"
        #print b
        #print user_name
        #print user_password

        #b = a.get()
        #print b
        #key = db.get(b)
        #return key


class Welcome(Handler):
    def get(self):
        general_posts = db.GqlQuery("SELECT * FROM Blog order by created desc limit 10")
        self.render("blog_welcome.html", posts=general_posts, current_page="blog_welcome")

    def post(self):
        if self.request.POST.get("myPostsPage"):
            chocolate = ""
            ##query of blogs from the user
            ##if render with error not no post to show.
            ## else render with user post
            # print "my Post Page"
        elif self.request.POST.get("myProfile"):
            chocolate = ""
            ## render: username & password & member since
            ## option to change username and password
            # print "my profile"
        elif self.request.POST.get("userNewPost"):
            self.redirect_to("NewPost")


class NewPost(Handler):
    def get(self):
        # type: () -> object
        template_name = "blog_entry.html"
        cookie_value = self.request.cookies.get("name")
        #print cookie_value
        if cookie_value is not None and self.cookie_checker(cookie_value):
            self.render(template_name, title="", content="", current_page="registered_blog_entry")
        else:
            self.render(template_name, title="", content="", current_page="nonRegisteredUser")

    def post(self):
        template_error = "blog_entry.html"
        current_page = self.request.get("current_page")
        blog_title = self.request.get("title")
        blog_content = self.request.get("content")
        title_status = self.check_entry("title", blog_title)
        content_status = self.check_entry("content", blog_content)
        cookie_value = self.request.cookies.get("name")


        #print title_status
        #print content_status

        #print cookie_value

        if self.request.POST.get("newPostButton"):
            if cookie_value is not None:
                user_name = self.cookie_checker(cookie_value)
                if user_name:
                    if title_status is True and content_status is True:
                        #print "post NewPost"
                        new_database_entry = Blog(title=blog_title, content=blog_content, user_name=user_name)
                        new_database_entry.put()
                        cursor_rows = db.GqlQuery("SELECT * FROM Blog")
                        # print new_database_entry.key().id()
                        id_created = new_database_entry.key().id()
                        self.redirect_to("NewCreatedPost", blog_id=id_created)
                    elif title_status is not True and content_status is not True:
                        user_error = title_status + ". " + content_status
                        self.render(template_error, error=user_error, current_page="registered_blog_entry")
                    elif title_status is True:
                        #print title_status
                        self.render(template_error, title=blog_title, error=content_status, current_page="registered_blog_entry")
                    else:
                        #print content_status
                        self.render(template_error, content=blog_content, error=title_status, current_page="registered_blog_entry")
            else:
                self.redirect_to("Login")
        elif self.request.POST.get("allPosts"):
            self.redirect_to("AllPosts")
        elif self.request.POST.get("myProfile"):
            self.redirect_to("AllPosts")
        elif self.request.POST.get("myPostsPage"):
            self.redirect_to("UserPosts")





class AllBlogPosts(Handler):
    def get(self):
        # type: () -> object
        a = self.request
        cookie_value = self.request.cookies.get("name")
        #print cookie_value
        if cookie_value is not None and self.cookie_checker(cookie_value):
            user_name = self.cookie_checker(cookie_value)
            template_name = "blog_posts.html"
            posts = db.GqlQuery("SELECT * FROM Blog order by created desc limit 10")
            self.render(template_name, posts=posts, user=user_name, current_page="registered_blog_posts")
    def post(self):
        cookie_value = self.request.cookies.get("name")
        if cookie_value is not None and self.cookie_checker(cookie_value):
            if self.request.POST.get("userNewPost"):
                self.redirect_to("NewPost")
            elif self.request.POST.get("myProfile"):
                self.redirect_to("AllPosts")
            elif self.request.POST.get("myPostsPage"):
                self.redirect_to("UserPosts")


class UserBlogPosts(Handler):
    def get(self):
        template_name = "user_blog_posts.html"
        cookie_value = self.request.cookies.get("name")
        #print self.request.arguments()
        #print cookie_value
        if cookie_value is not None and self.cookie_checker(cookie_value):
            user_name = self.cookie_checker(cookie_value)
            user_posts = db.GqlQuery("SELECT * FROM Blog WHERE user_name = :user_name", user_name=user_name)

            self.render(template_name, posts=user_posts, current_page="registered_user_blog_posts")
            #print user_posts

    def post(self):
        cookie_value = self.request.cookies.get("name")
        if cookie_value is not None and self.cookie_checker(cookie_value):
            if self.request.POST.get("allPosts"):
                self.redirect_to("AllPosts")
            elif self.request.POST.get("myProfile"):
                self.redirect_to("AllPosts")
            elif self.request.POST.get("userNewPost"):
                self.redirect_to("NewPost")
            else:
                post_number = self.request.POST.multi._items[0][0]
                print post_number
        # post_number1 = post_number.split("'")
        # print post_number1
        # bla = post_number1[4].split(",")
        # bla1 = bla[1]
        # #print bla[7]
        # user_name = post_number1[1]
        # title = post_number1[3]
                q = Blog.get(post_number)
                bla = q.key().id()

        #print bla2
                print q.content
                self.redirect_to("NewCreatedPost", blog_id=bla)


         #q = db.GqlQuery("SELECT FROM Blog WHERE user_name = :user_name ", user_name=user_name)
        # for post in q:
        #     print post.__getattribute__("key")
        #     print post.created
        #     print

            #b = q.filter("user_name=", user_name)

        #c=  q.get()

        #print title
        #print q

        #print date_created  esta dando solo el anio

        a = self.request.POST.get("edit-[0-9]")
        print a
        if self.request.POST.get("Edit"):
            print "bla"
            self.redirect_to("Edit")



class SinglePost(Handler):
    def get(self, blog_id):

        referer = self.request.referer
        print self.request
        print referer
        editStr = "edit/"+blog_id
        selfStr = "blog/"+blog_id


           #key = db.Key.from_path("Blog", int(blog_id))
           #post = db.get(key)
           #print post.user_name
        if selfStr in referer:
            self.redirect_to("Edit", blog_id=blog_id)

        # elif self.request.POST.get("newPostButton"):
        #     print "bla"
        # else:
        # # print key
        else:
            key = db.Key.from_path("Blog", int(blog_id))
            post = db.get(key)
            self.render("blog_redirect.html", post=post)

    def post(self, blog_id):
        print "bla"
        key = db.Key.from_path("Blog", int(blog_id))
        post = db.get(key)
        #current_page = self.request.get("current_page")
        blog_title = self.request.get("title")
        blog_content = self.request.get("content")
        title_status = self.check_entry("title", blog_title)
        content_status = self.check_entry("content", blog_content)
        cookie_value = self.request.cookies.get("name")
        if cookie_value is not None:
            user_name = self.cookie_checker(cookie_value)
            if user_name:
                if self.request.POST.get("edit"):
                    self.redirect_to("Edit")
                # if title_status is True and content_status is True:
                #     print "post NewPost"
                #     post.title = blog_title
                #     post.content = blog_content
                #     post.put()
                #     self.redirect_to("NewCreatedPost", blog_id=blog_id)
                # elif title_status is not True and content_status is not True:
                #     user_error = title_status + ". " + content_status
                #     self.render(template_error, error=user_error, current_page="registered_blog_entry")
                # elif title_status is True:
                #     # print title_status
                #     self.render(template_error, title=blog_title, error=content_status, current_page="registered_blog_entry")
                # else:
                #     # print content_status
                #     self.render(template_error, content=blog_content, error=title_status, current_page="registered_blog_entry")
        else:
            self.redirect_to("Login")


class EditSinglePost(Handler):
    def get(self, blog_id):
        key = db.Key.from_path("Blog", int(blog_id))
        post = db.get(key)
        self.render("blog_entry.html", title=post.title, content=post.content)
    def post(self, blog_id):
        print "a"
        self.redirect_to("NewCreatedPost", blog_id=blog_id)









app = webapp2.WSGIApplication([webapp2.Route('/', handler=Handler, name='Home'),
                               webapp2.Route('/blog/blogposts', handler=AllBlogPosts, name='AllPosts'),
                               webapp2.Route('/blog/newpost', handler=NewPost, name='NewPost'),
                               webapp2.Route(r'/blog/<blog_id:[0-9]+>', handler=SinglePost, name='NewCreatedPost'),
                               webapp2.Route(r'/blog/edit/<blog_id:[0-9]+>', handler=EditSinglePost, name='Edit'),
                               webapp2.Route('/blog/signup', handler=SignUp, name='SignUp'),
                               webapp2.Route('/blog/login', handler=LogIn, name='Login'),
                               webapp2.Route('/blog/welcome', handler=Welcome, name='Welcome'),
                               webapp2.Route('/blog/myposts', handler=UserBlogPosts, name="UserPosts"),
                               ],
                               debug=True)

# app = webapp2.WSGIApplication([('/', Handler), ('/blog', BlogPosts), ('/blog/newpost', NewPost), ], debug=True)
