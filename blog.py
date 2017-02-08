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
    likes = db.IntegerProperty(default=0)
    last_modified = db.DateTimeProperty()
    deletion_date = db.DateTimeProperty(default=None)


class User(db.Model):
    user_name = db.StringProperty(required=True)
    user_password = db.StringListProperty(required=True)
    user_email = db.EmailProperty(required=False)
    user_member_since = db.DateTimeProperty(auto_now_add=True)

class Likes(db.Model):
    blog_id = db.StringProperty(required=True)
    user_name= db.StringProperty(required=True)

class Comments(db.Model):
    blog_id = db.StringProperty(required=True)
    user_name = db.StringProperty(required=True)
    comment = db.StringProperty(required=True)
    created =db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty()
    deletion_date = db.DateTimeProperty(default=None)






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

    def get_key_by_user_name(self, user_name):
        query = User.all(keys_only=True)
        user_key_query = query.filter("user_name =", user_name)
        user_key = user_key_query.get()
        return user_key

    def cookie_checker(self, cookie_name):
        split_cookie_value = cookie_name.split("|")
        hash_value = split_cookie_value[1]
        user_name = split_cookie_value[0]
        db_user_key = self.get_key_by_user_name(user_name)

        if db_user_key is None:
            print db_user_key
            return False
        hash_status = self.hash_validator(hash_value, db_user_key)
        #print hash_status
        if hash_status is True:
            return user_name
            print user_name
        else:
            return hash_status


    def hash_validator(self, hash_value, user_key):
        user_entity = User.get(user_key)
        user_password = user_entity.user_password
        if user_password[0] == hash_value:
            return True
        else:
            return False

    def entry_validator(self, entry_name, entry):
        min_length_required = 0
        entry_without_spaces = entry.replace(" ", "")
        error1_response = "Please add a"
        error2_response = "Please enter a minimum of"
        if entry_name == "title":
            min_length_required = 2
        elif entry_name == "comment":
            min_length_required = 1
        else:
            min_length_required = 1

        if len(entry_without_spaces) == 0:
            return error1_response + " " + entry_name
        elif len(entry_without_spaces) < min_length_required:
            return error2_response + " " + str(min_length_required) + " " + entry_name
        else:
            return True

    def name_validator(self, userName):
        error_name = "Please enter a valid name"
        if all(result != " " for result in userName):
            if 3 < len(userName) < 25:
                return self.db_search(userName)
            else:
                return error_name
        else:
            return error_name

    def db_search(self, userName):
        query = User.all(keys_only=True)
        query.filter("user_name =", userName)
        error_name_database = "This name is already in use, please enter a new one"
        key = query.get()
        if key == None:
            return True
        else:
            return error_name_database


    def hash_it_with_salt(self, name, password):
        ##With a lil help from stackoverflow: http://stackoverflow.com/questions/2257441/random-string-generation-with-upper-case-letters-and-digits-in-python/23728630#23728630
        salt = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for x in xrange(10))
        hash = hashlib.sha512(name + password + salt).hexdigest()
        return [hash, salt]

    def logout(self):
        self.response.delete_cookie("name")
        self.redirect_to("Login")

    def set_cookie(self, hash, userName):
        value = userName + "|" + hash
        self.response.set_cookie("name", value)

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
        if email.find(' ') == -1 and email.find("@") != -1:
            if email[-4:] == ".com":
                return True
        return error_valid_email

    def delete_entity(self, kind, id_entity):
        key = db.Key.from_path(kind, int(id_entity))
        entity = db.get(key)
        entity.delete()


class SignUp(Handler):
    def get(self):
        cookie_value = self.request.cookies.get("name")
        template_name = "blog_signup.html"
        if cookie_value is not None:
            valid_cookie = self.cookie_checker(cookie_value)
            #print valid_cookie
            if valid_cookie is not False:
                self.redirect_to("AllPosts", current_page="logged_user")
            else:
                self.render( template_name, current_page="signUp")
                #print "bla"
        else:
            self.render(template_name, user_name="", user_password="", user_email="", current_page="signUp")

    def post(self):
        name = self.request.get("userName")
        name_status = self.name_validator(name)
        password = self.request.get("userPassword")
        password_confirmation = self.request.get("passwordConfirmation")
        password_status = self.password_validator(password, password_confirmation)
        email = self.request.get("userEmail")
        self.email_validator(email)
        status_result = []
        email_status = ""
        if len(email) > 0 and email.isspace() is not True:
            email_status = self.email_validator(email)
            status_result.append(name_status)
            status_result.append(password_status)
            status_result.append(email_status)
            if all(result == True for result in status_result):
                self.save_in_db(name, password, email)
                self.redirect_to("AllPosts", current_page="logged_user")
            else:
                self.render("blog_signup.html", user_name=name, user_password="", user_email=email,
                            name_status=name_status, password_status=password_status, email_status=email_status,
                            current_page="signUp")
        else:
            status_result.append(name_status)
            status_result.append(password_status)
            if all(result == True for result in status_result):
                self.save_in_db(name, password)
                print "signup"
                self.redirect_to("AllPosts", current_page="logged_user")
            else:
                self.render("blog_signup.html", user_name=name, user_password="", user_email="",
                            name_status=name_status, password_status=password_status, email_status=email_status, current_page="signUp" )


    def save_in_db(self, userName, userPassword, email=None):
        userEmail = email
        encrypt_password = self.hash_it_with_salt(userName, userPassword)
        new_database_entry = User(user_name=userName, user_password=encrypt_password, user_email=userEmail)
        User_instance = new_database_entry.put()
        hash = encrypt_password[0]
        self.set_cookie(hash, userName)


    def hash_it_with_salt(self, name, password):
        ##With a lil help from stackoverflow: http://stackoverflow.com/questions/2257441/random-string-generation-with-upper-case-letters-and-digits-in-python/23728630#23728630
        salt = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for x in xrange(10))
        hash = hashlib.sha512(name + password + salt).hexdigest()
        return [hash, salt]



class LogIn(Handler):
    def get(self):
        cookie_value = self.request.cookies.get("name")
        template_name = "blog_login.html"
        if cookie_value is not None:
            valid_cookie = self.cookie_checker(cookie_value)
            #print valid_cookie
            if valid_cookie is not False:
                self.redirect_to("AllPosts", current_page="logged_user")
            else:
                self.render(template_name, current_page="login")
                #print "bla"
        else:
            self.render(template_name, current_page="login")



    def post(self):
        user_name = self.request.get("name")
        ##http://stackoverflow.com/questions/21505255/identify-which-submit-button-was-clicked-in-django-form-submit
        user_password = self.request.get("password")
        template_name = "blog_login.html"
        if all(result != " " for result in user_name):
            key = self.get_key_by_user_name(user_name)

            if key == None:
                #print "non"
                self.render(template_name, current_page="login", error1="This username is not registered", user_name=user_name, user_password= user_password)
            else:
                user = db.get(key)
                #print user.user_password
                user_saved_password = user.user_password
                user_hash = user_saved_password[0]
                user_salt = user_saved_password[1]
                last_hash = self.get_hash_with_salt(user_name, user_password, user_salt)
                #print last_hash
                hash_status  = self.hash_validator(last_hash, key)
                #print hash_status
                if user_hash == last_hash:
                    self.set_cookie(user_hash, user_name)
                    self.redirect_to("AllPosts", current_page="logged_user")
                else:
                     self.render(template_name, current_page="login", error2="Incorrect Password", user_name=user_name, user_password= user_password)

class NewPost(Handler):
    def get(self):
        # type: () -> object
        template_name = "blog_entry.html"
        cookie_value = self.request.cookies.get("name")
        #print cookie_value
        if cookie_value is not None and self.cookie_checker(cookie_value):
            self.render(template_name, title="", content="", current_page="logged_user")
        else:
            self.render(template_name, title="", content="", current_page="nonRegisteredUser")

    def post(self):
        template_error = "blog_entry.html"
        current_page = self.request.get("current_page")
        blog_title = self.request.get("title")
        blog_content = self.request.get("content")
        title_status = self.entry_validator("title", blog_title)
        content_status = self.entry_validator("content", blog_content)
        cookie_value = self.request.cookies.get("name")

        if self.request.POST.get("newPostButton"):
            if cookie_value is not None:
                user_name = self.cookie_checker(cookie_value)
                if user_name:
                    if title_status is True and content_status is True:
                        new_database_entry = Blog(title=blog_title, content=blog_content, user_name=user_name )
                        new_database_entry.put()
                        cursor_rows = db.GqlQuery("SELECT * FROM Blog")
                        id_created = new_database_entry.key().id()
                        self.redirect_to("NewCreatedPost", blog_id=id_created)
                    elif title_status is not True and content_status is not True:
                        user_error = title_status + ". " + content_status
                        self.render(template_error, error3=user_error, current_page="logged_user")
                    elif title_status is True:
                        self.render(template_error, title=blog_title, error2=content_status, current_page="logged_user")
                    else:
                        self.render(template_error, content=blog_content, error1=title_status, current_page="logged_user")
            else:
                self.redirect_to("Login")

        elif self.request.POST.get("logout"):
            self.logout()

class AllBlogPosts(Handler):
    def get(self):
        a = self.request
        cookie_value = self.request.cookies.get("name")
        posts = db.GqlQuery("SELECT * FROM Blog order by created desc limit 10")
        template_name = "blog_posts.html"
        print self.request.referer



        if cookie_value is not None and self.cookie_checker(cookie_value):
            user_name = self.cookie_checker(cookie_value)
            self.render(template_name, posts=posts, user=user_name, current_page="logged_user")
        else:
            #print "non cookie"
            self.render(template_name, posts=posts,  current_page="nonRegisteredUser")





class UserBlogPosts(Handler):
    def get(self):
        template_name = "user_blog_posts.html"
        cookie_value = self.request.cookies.get("name")

        if cookie_value is not None and self.cookie_checker(cookie_value):
            user_name = self.cookie_checker(cookie_value)
            user_posts = db.GqlQuery("SELECT * FROM Blog WHERE user_name = :user_name", user_name=user_name)
            self.render(template_name, posts=user_posts, current_page="logged_user")
        else:
            self.redirect_to("Login")

    def post(self):
        cookie_value = self.request.cookies.get("name")
        if cookie_value is not None and self.cookie_checker(cookie_value):
                post_number = self.request.POST.multi._items[0][0]
                q = Blog.get(post_number)
                bla = q.key().id()
                logged_user_name= self.cookie_checker(cookie_value)
                self.redirect_to("NewCreatedPost", blog_id=bla, user=logged_user_name)

        if self.request.POST.get("Edit"):
            #print "bla"
            self.redirect_to("Edit")
        elif self.request.POST.get("logout"):
            self.logout()



class SinglePost(Handler):
    def get(self, blog_id):

        cookie_value = self.request.cookies.get("name")
        if cookie_value is not None and self.cookie_checker(cookie_value):
           self.render_base(blog_id)
        else:
            cookie_value = self.request.cookies.get("name")
            ##logged_user_name = self.cookie_checker(cookie_value)
            blog_key = db.Key.from_path("Blog", int(blog_id))
            blog = db.get(blog_key)
            blog = db.get(blog_key)
            ##user_like = self.give_key_like(blog_id, logged_user_name)
            blog_author = blog.user_name
            likes_counter = blog.likes

            comments = db.GqlQuery("SELECT * FROM Comments WHERE blog_id = :blog_id order by created desc",
                                   blog_id=blog_id)

            self.render("blog_redirect.html", post=blog, current_page="nonRegisteredUser",
                        user_name=None, likes=likes_counter,
                        blog_author=blog_author, comments=comments)


    def render_base(self, blog_id, current_comment="", deleted_comment=""):
        cookie_value = self.request.cookies.get("name")
        logged_user_name = self.cookie_checker(cookie_value)
        blog_key = db.Key.from_path("Blog", int(blog_id))
        blog = db.get(blog_key)
        blog = db.get(blog_key)
        user_like = self.give_key_like(blog_id, logged_user_name)
        blog_author = blog.user_name
        likes_counter = blog.likes




        comments = db.GqlQuery("SELECT * FROM Comments WHERE blog_id = :blog_id order by created desc", blog_id=blog_id)


        self.render("blog_redirect.html", post=blog, current_page="logged_user",
                    user_name=logged_user_name, likes=likes_counter,
                    blog_author=blog_author, comments=comments, current_comment=current_comment, user_like=user_like,
                    deleted_comment=deleted_comment)

    def post(self, blog_id):
        #print "bla"
        key = db.Key.from_path("Blog", int(blog_id))
        post = db.get(key)
        #current_page = self.request.get("current_page")
        blog_title = self.request.get("title")
        blog_content = self.request.get("content")
        title_status = self.entry_validator("title", blog_title)
        content_status = self.entry_validator("content", blog_content)
        cookie_value = self.request.cookies.get("name")


        # for b in blass:
        #      print b
        if cookie_value is not None:
            user_name = self.cookie_checker(cookie_value)
            if user_name:
                #split_cookie_value = cookie_name.split("|")
                #hash_value = split_cookie_value[1]
                if self.request.POST.get("edit"):

                    self.redirect_to("Edit")
                elif self.request.POST.get("like"):
                    #logged_user_key = self.get_key_by_user_name(user_name)
                    #logged_user_key = self.get_key_by_user_name(user_name)
                    cookie_value = self.request.cookies.get("name")
                    logged_user_name = self.cookie_checker(cookie_value)
                    blog_key = db.Key.from_path("Blog", int(blog_id))

                    blog = db.get(blog_key)
                    user_like = self.like_validator(blog_id, logged_user_name)
                    blog_author = blog.user_name
                    likes_counter = blog.likes
                    comments = db.GqlQuery("SELECT * FROM Comments WHERE blog_id = :blog_id order by created desc",
                                           blog_id=blog_id)
                    #TODO commentvalidator, likevalidator, add comment/like db

                    #self.like_validator(blog_id, user_name)
                    self.render("blog_redirect.html", post=blog, current_page="logged_user",
                                user_name=logged_user_name, likes=likes_counter, user_like=user_like,
                                blog_author=blog_author, comments=comments)

                    #self.redirect_to("NewCreatedPost", blog_id=blog_id)
                elif self.request.POST.get("comment"):

                    user_comment = self.request.get("comment")
                    #print user_comment
                    comment_status = self.entry_validator("comment", user_comment)
                    # comment_status

                    if comment_status is True:
                        #self.render_base(blog_id, current_comment=user_comment)

                        cookie_value = self.request.cookies.get("name")
                        logged_user_name = self.cookie_checker(cookie_value)
                        blog_key = db.Key.from_path("Blog", int(blog_id))
                        blog = db.get(blog_key)
                        blog = db.get(blog_key)
                        user_like = self.does_user_like_it(blog_id, logged_user_name)
                        blog_author = blog.user_name
                        likes_counter = blog.likes

                        comments = db.GqlQuery(
                            "SELECT * FROM Comments WHERE blog_id = :blog_id order by created limit 10",
                            blog_id=blog_id)

                        self.render("blog_redirect.html", post=blog, current_page="logged_user",
                                    user_name=logged_user_name, likes=likes_counter, user_like=user_like,
                                    blog_author=blog_author, comments=comments, current_comment=user_comment)
                        comment_entity = Comments(blog_id=blog_id, user_name=user_name, comment=user_comment)
                        comment_entity.put()
                        #self.redirect_to("NewCreatedPost", blog_id=blog_id)
                    else:
                        self.render_base(blog_id, current_comment=user_comment)
                elif self.request.POST.get("delete_blog"):
                    self.delete_entity("Blog", blog_id)
                    self.redirect_to("UserPosts")
                elif self.request.POST.get("logout"):
                    self.logout()
                else:
                    post_data = self.request.POST
                    #print post_data
                    post_data_iter_dict = post_data.iteritems()
                    for key, value in post_data_iter_dict:
                        if value == "delete":
                            blog_id_unicode = key
                            blog_id_int= int(key)
                            blog_id_str= str(blog_id_int)

                    key_comment = db.Key.from_path("Comments", int(blog_id_str))
                    #print key_comment
                    entity = db.get(key_comment)
                    q = Comments.all()
                    cookie_value = self.request.cookies.get("name")
                    logged_user_name = self.cookie_checker(cookie_value)
                    blog_key = db.Key.from_path("Blog", int(blog_id))
                    blog = db.get(blog_key)
                    blog = db.get(blog_key)
                    user_like = self.does_user_like_it(blog_id, logged_user_name)
                    blog_author = blog.user_name
                    likes_counter = blog.likes
                    comments = db.GqlQuery("SELECT * FROM Comments WHERE blog_id = :blog_id ", blog_id=blog_id)
                    self.render("blog_redirect.html", post=blog, current_page="logged_user",
                            user_name=logged_user_name, likes=likes_counter, user_like=user_like,
                            blog_author=blog_author, comments=comments,
                            deleted_comment=key_comment)
                    self.delete_entity("Comments", blog_id_str)




                    #self.delete_entity("Comments", blog_id_unicode)
                    #self.render_base(blog_id, deleted_comment=blog_id_unicode)

        else:
            self.redirect_to("Login")


    #Render base
    #Checks if user has liked the post
    #Checks
    def like_validator(self, blog_id, logged_user):

        #new_like_entity = Likes(blog_id=blog_id, user_name=logged_user)
        #new_like_entity.put()
        #query
        #"rosado"
        query_likes= Likes.all(keys_only=True)
        query_likes.filter("blog_id", blog_id).filter("user_name", logged_user)
        key_likes = query_likes.get()
        print key_likes
        comments = db.GqlQuery("SELECT * FROM Likes WHERE blog_id = :blog_id and user_name = :user_name ", blog_id=blog_id, user_name=logged_user)
        #for c in comments:
         #   print c
        # #print a.__sizeof__()
        # r = a.
        # print r.get()
        # key_likes = query_likes.get()
        # print key_likes

        key_blog = db.Key.from_path("Blog", int(blog_id))
        blog_entity = db.get(key_blog)
        post_author = blog_entity.user_name

        if key_likes == None:
            print "nop hay"
            new_like_entity = Likes(blog_id=blog_id, user_name=logged_user)
            new_like_entity.put()
            likes_counter = blog_entity.likes +1
            # #print likes_counter
            blog_entity.likes = likes_counter
            blog_entity.put()
            return True



            #add 1 to counter
        else:
            print "si hay"
            #print "delete"
            #print key_likes
            like_entity = db.get(key_likes)
            print like_entity


            print "a"
            like_entity.delete()
            likes_counter = blog_entity.likes - 1
            blog_entity.likes = likes_counter
            blog_entity.put()
            return False

    def give_key_like(self, blog_id, logged_user):

        query_likes = Likes.all(keys_only=True)
        query_likes.filter("blog_id", blog_id).filter("user_name", logged_user)
        key_likes = query_likes.get()
        #print "key"
        if key_likes == None:
            return True
        else:
            return False


class EditSinglePost(Handler):
    def get(self, blog_id):
        key = db.Key.from_path("Blog", int(blog_id))
        post = db.get(key)
        cookie_value = self.request.cookies.get("name")
        if cookie_value is not None and self.cookie_checker(cookie_value):

            self.render("blog_entry.html", title=post.title, content=post.content, current_page="logged_user")

    def post(self, blog_id):
        #print "a"
        key = db.Key.from_path("Blog", int(blog_id))
        post = db.get(key)
        blog_title = self.request.get("title")
        blog_content = self.request.get("content")
        title_status = self.entry_validator("title", blog_title)
        content_status = self.entry_validator("content", blog_content)
        cookie_value = self.request.cookies.get("name")
        if cookie_value is not None and self.cookie_checker(cookie_value):
            if self.request.POST.get("newPostButton"):
                if title_status is True and content_status is True:
                    #print "post NewPost"
                    post.title = blog_title
                    post.content = blog_content
                    post.put()
                    self.redirect_to("NewCreatedPost", blog_id=blog_id, current_page="logged_user")
                elif title_status is not True and content_status is not True:
                    user_error = title_status + ". " + content_status
                    self.render(template_error, error=user_error, current_page="logged_user")
                elif title_status is True:
                    # print title_status
                    self.render(template_error, title=blog_title, error=content_status, current_page="logged_user")
                else:
                    # print content_status
                    self.render(template_error, content=blog_content, error=title_status, current_page="logged_user")

            elif self.request.POST.get("logout"):
                self.logout()
        else:
            self.redirect_to("Login")

class UserProfile(Handler):
    #TODO add a cancel button on the changes form
    def get(self):
        cookie_value = self.request.cookies.get("name")
        if cookie_value is not None and self.cookie_checker(cookie_value):
            user_name = self.cookie_checker(cookie_value)
            key = self.get_key_by_user_name(user_name)
            user = db.get(key)
            user_email = user.user_email
            self.render("blog_my_profile.html", user_name=user_name, password="-----", email=user_email, current_page="logged_user")
        else:
            self.redirect_to("Login")


    def post(self):
        cookie_value = self.request.cookies.get("name")
        user_name = self.cookie_checker(cookie_value)
        key = self.get_key_by_user_name(user_name)
        #print key
        user = db.get(key)
        user_hash_salt = user.user_password
        user_salt = user_hash_salt[1]
        user_saved_hash = user_hash_salt[0]
        user_email = user.user_email

        if self.request.POST.get("editName"):
            self.render("blog_my_profile.html", user_name=user_name, password="-----", email="", edit_name="yes", current_page="logged_user")
        elif self.request.POST.get("editPassword"):
            self.render("blog_my_profile.html", user_name=user_name, password="-----", email="", edit_password="yes", current_page="logged_user")
        elif self.request.POST.get("editEmail"):
            self.render("blog_my_profile.html", user_name=user_name, password="-----", email=user_email, edit_email="yes", current_page="logged_user")
#kindof
        if self.request.POST.get("saveName"):

            new_name = self.request.get("userName")
            name_status= self.name_validator(new_name)
            user_password = self.request.get("userPassword")
            entered_password_with_hash = self.get_hash_with_salt(user_name, user_password, user_salt)
            if name_status is True and entered_password_with_hash == user_saved_hash:
                new_hash_salt = self.hash_it_with_salt(new_name, user_password)
                new_hash = new_hash_salt[0]
                user.user_name=new_name
                user.user_password=new_hash_salt
                user.put()
                self.set_cookie(new_hash, new_name)
                self.render("blog_my_profile.html", user_name=new_name, password="-----", email="", edit_name="no", current_page="logged_user")

                #change blog name
                blogs_by_user= db.GqlQuery("SELECT * FROM Blog WHERE user_name = :user_name ", user_name=user_name)

                for b in blogs_by_user:
                    b.user_name = new_name
                    b.put()
                    #print b.user_name


                comments_by_user = db.GqlQuery("SELECT * FROM Comments WHERE user_name = :user_name ", user_name=user_name)
                for c in comments_by_user:
                    c.user_name = new_name
                    b.put()
                    #print c.user_name
                #for u in user_key:
                   # print u

                likes_by_user = db.GqlQuery("SELECT * FROM Likes WHERE user_name = :user_name ",
                                            user_name=user_name)

                if likes_by_user != None:
                    for l in likes_by_user:
                        l.user_name = new_name
                        l.put()
                        #print l.user_name


                #return user_key



            elif name_status is not True and entered_password_with_hash == user_saved_hash:
                #print "eror"
                self.render("blog_my_profile.html", user_name=user_name, password="-----", email="", error=name_status, edit_name="yes", current_page="logged_user")
            elif name_status is True and entered_password_with_hash != user_saved_hash:
                self.render("blog_my_profile.html", user_name=user_name, password="-----", email="", error="Please enter a valid password", edit_name="yes", current_page="logged_user")
            else:
                self.render("blog_my_profile.html", user_name=user_name, password="-----", email="", error="Please enter a valid name and password", edit_name="yes", current_page="logged_user")

        elif self.request.POST.get("savePassword"):
           new_password= self.request.get("newPassword")
           new_password_confirmation = self.request.get("confirmNewPassword")
           user_password = self.request.get("currentUserPassword")
           entered_password_with_hash = self.get_hash_with_salt(user_name, user_password, user_salt)
           password_status = self.password_validator(new_password, new_password_confirmation)
           if password_status is True and entered_password_with_hash == user_saved_hash:
                new_saved_password = self.hash_it_with_salt(user_name, new_password)
                #print user_name

                new_hash = new_saved_password[0]
                #print new_saved_password
                user.user_password = new_saved_password
                user.put()
                self.set_cookie(new_hash, user_name)
                self.render("blog_my_profile.html", user_name=user_name, password="-----", email="", edit_password="no", current_page="logged_user")
           elif password_status is not True and entered_password_with_hash == user_saved_hash:
               self.render("blog_my_profile.html", user_name=user_name, password="-----", email="", error_password=password_status, edit_password="yes", current_page="logged_user")
           elif password_status is True and entered_password_with_hash != user_saved_hash:
               password_status = "Your current password is incorrect"
               self.render("blog_my_profile.html", user_name=user_name, password="-----", email="", error_password=password_status, edit_password="yes", current_page="logged_user")
           else:
               password_status = password_status + " / Your current password is incorrect"
               self.render("blog_my_profile.html", user_name=user_name, password="-----", email="", error_password=password_status, edit_password="yes", current_page="logged_user")

        elif self.request.POST.get("saveEmail"):
            new_email = self.request.get("newEmail")
            email_status = self.email_validator(new_email)

            if email_status is True:
                user.user_email = new_email
                user.put()
                self.render("blog_my_profile.html", user_name=user_name, password="-----", email=new_email, edit_email="no")
            elif email_status is not True:
                self.render("blog_my_profile.html", user_name=user_name, password="-----", email=new_email, error_email=email_status, edit_email="yes")


class LogOut(Handler):
    def get(self):
        self.response.delete_cookie("name")
        self.redirect_to("Login")


app = webapp2.WSGIApplication([webapp2.Route('/', handler=Handler, name='Home'),
                               webapp2.Route('/blog/blogposts', handler=AllBlogPosts, name='AllPosts'),
                               webapp2.Route('/blog/newpost', handler=NewPost, name='NewPost'),
                               webapp2.Route(r'/blog/<blog_id:[0-9]+>', handler=SinglePost, name='NewCreatedPost'),
                               webapp2.Route(r'/blog/edit/<blog_id:[0-9]+>', handler=EditSinglePost, name='Edit'),
                               webapp2.Route('/blog/signup', handler=SignUp, name='SignUp'),
                               webapp2.Route('/blog/login', handler=LogIn, name='Login'),
                               webapp2.Route('/blog/myposts', handler=UserBlogPosts, name="UserPosts"),
                               webapp2.Route('/blog/myprofile', handler=UserProfile, name="UserProfile"),
                               webapp2.Route('/blog/logout', handler=LogOut, name="LogOut"),

                               ],
                               debug=True)

