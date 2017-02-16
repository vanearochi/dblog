import os
import webapp2
import jinja2
from webapp2 import RequestHandler
from google.appengine.ext import db
import random
import string
import hashlib
import datetime

path_template_dir = os.path.join(os.path.dirname(__file__), "templates")
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(path_template_dir), autoescape=True, trim_blocks=True)



class Blog(db.Model):
    """Blog database model
    Attributes:
        title: A string representation the blog title
        content: A string representation the blog content
        user_name: A string representation of the blog's author
        created: An integer representation of the date and time of blog's creation.
        show_created: An integer representation of the blog's date creation that will be displayed
        likes: An integer count of the likes that the blog has received
        last_modified: An integer representation of the date and time of the last time the blog was modified, if any.
        deletion_time: An integer representation of the date and time of blog's deletion, helps with soft deletion
    """
    title = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    user_name = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    show_created = db.DateProperty(auto_now_add=True)
    likes = db.IntegerProperty(default=0)
    last_modified = db.DateTimeProperty()
    deletion_date = db.DateTimeProperty(default=None)


class User(db.Model):
    """User database model
    Attributes:
        user_name: String representation of the name of the owner of a blog account
        user_password: String representation of the account owner's password
        user_email: String representation of the account owner's email
        user_member_since: An integer representation of the date and time of the account creation
    """
    user_name = db.StringProperty(required=True)
    user_password = db.StringListProperty(required=True)
    user_email = db.EmailProperty(required=False)
    user_member_since = db.DateTimeProperty(auto_now_add=True)


class Likes(db.Model):
    """Likes database Model
    Attributes:
        blog_id: String representation of the id of the blog liked
        user_name: String representation of the user name that liked the post
        deletion_date: An integer representation of the date and time that user unliked the post
        """
    blog_id = db.StringProperty(required=True)
    user_name = db.StringProperty(required=True)
    deletion_date = db.DateTimeProperty(default=None)


class Comments(db.Model):
    """Comments database Model:
    Attributes:
        blog_id: String representation of the id of the blog commented.
        user_name: String representation of the  user name that commented the post.
        created: An integer representation of the date and time of the comment's creation.
        last_modified: An integer representation of the date and time of the last time the commented was modified.
        deletion_date: An integer representation of the date and time that user delete the comment.
        """
    blog_id = db.StringProperty(required=True)
    user_name = db.StringProperty(required=True)
    comment = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty()
    deletion_date = db.DateTimeProperty(default=None)


class Handler(RequestHandler):
    """ Handles functions that are used by more than one class."""
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def get_hash_with_salt(self, name, password, salt):
        """Hashes a combination of strings.
        Args:
            name: A string representing the user's name
            password: A string representing the user's password
            salt: A string representing a unique combination of characters

        Returns:
            A hashed value
        """
        user_hash = hashlib.sha512(name + password + salt).hexdigest()
        return user_hash

    def get_key_by_user_name(self, user_name):
        """Search for an entity key
        Args:
            user_name: A string representing the user's name property of a User kind entity.

        Returns:
            The key object for a User's instance.

        """
        query = User.all(keys_only=True)
        # TODO: Make sure this is a lookup by key.
        user_key_query = query.filter("user_name =", user_name)
        user_key = user_key_query.get()
        return user_key

    def cookie_validator(self, cookie_name):
        """Checks if the cookie name passed is valid according to the
        Args:
            cookie_name: String representing the cookie's name that is formed by the user_name and his created hash_value.
        Returns:
            A string indicating if the cookie_name is valid or not.
        """
        split_cookie_value = cookie_name.split("|")

        user_name = split_cookie_value[0]
        hash_value = split_cookie_value[1]

        try:
            db_user_key = split_cookie_value[2]
        except IndexError:
            db_user_key = self.get_key_by_user_name(user_name)

        if db_user_key is None:
            return False
        hash_status = self.hash_validator(hash_value, db_user_key)

        if hash_status is True:
            return user_name

        else:
            return hash_status

    def hash_validator(self, hash_value, user_key):
        """Checks if the hash value passed is the same as the one stored for a particular key object
        Args:
            hash_value: String representing the hash stored at the current user's cookie.
            user_key: Key object of a particular instance.
        Returns:
            A boolean value indicating if the hash is valid or not
        """
        user_entity = User.get(user_key)
        user_password = user_entity.user_password
        if user_password[0] == hash_value:
            return True
        else:
            return False

    def entry_validator(self, entry_name, entry):
        """Checks if an entry is valid according to the requirements.
        Entry could be a title, comment or content, they differ in length and they should not only contain white spaces.
        Args:
            entry_name: String representing the type of entry (title, comment or content)
            entry: String representing the content  of the entry that the user submit
        Returns:
            A boolean value when validation passed and the type of error if validation doesn't passed
        """
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
        """Checks if the user name """
        error_name = "Please enter a valid name"
        user_no_spaces =  userName.replace(" ", "")
        if all(result != " " for result in user_no_spaces):
            if 3 < len(user_no_spaces) < 25:
                return self.db_search(user_no_spaces)
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

    def set_cookie(self, hash, user_name, key=None):
        value = user_name + "|" + hash
        if key is not None:
            value += "|" + str(key)

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

    def like_validator(self, blog_id, logged_user):

        user_key = self.get_key_by_user_name(logged_user)
        user_entity = db.get(user_key)
        query_likes = Likes.all(keys_only=True)
        query_likes.filter("blog_id", blog_id).filter("user_name", logged_user)
        key_likes = query_likes.get()
        key_run = query_likes.run()
        key_blog = db.Key.from_path("Blog", int(blog_id))
        blog_entity = db.get(key_blog)
        post_author = blog_entity.user_name

        if key_likes == None:
            return "Like"
        else:
            like_entity = db.get(key_likes)
            if like_entity.deletion_date is None:
                return "Liked"
            else:
                return "Like"

    def render_post(self, comment_error, blog_id, error):
        # key_words_paramenters = kwargs

        comment_error = comment_error
        cookie_value = self.request.cookies.get("name")
        logged_user_name = self.cookie_validator(cookie_value)
        blog_key = db.Key.from_path("Blog", int(blog_id))
        blog = db.get(blog_key)
        blog = db.get(blog_key)
        user_like = self.like_validator(blog_id, logged_user_name)
        blog_author = blog.user_name
        likes_counter = blog.likes

        comments = db.GqlQuery(
            "SELECT * FROM Comments WHERE blog_id = :blog_id and deletion_date = :deletion_date order by created desc",
            blog_id=blog_id, deletion_date=None)

        self.render("blog_redirect.html", post=blog, current_page="logged_user",
                    user_name=logged_user_name, likes=likes_counter,
                    blog_author=blog_author, comments=comments, user_like=user_like, comment_error=comment_error,
                    error=error)


class SignUp(Handler):
    def get(self):
        cookie_value = self.request.cookies.get("name")
        template_name = "blog_signup.html"
        if cookie_value is not None:
            valid_cookie = self.cookie_validator(cookie_value)
            # print valid_cookie
            if valid_cookie is not False:
                self.redirect_to("AllPosts")
            else:
                self.render(template_name, current_page="signUp")
                # print "bla"
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
                self.redirect_to("AllPosts")
            else:
                self.render("blog_signup.html", user_name=name, user_password="", user_email=email,
                            name_status=name_status, password_status=password_status, email_status=email_status,
                            current_page="signUp")
        else:
            status_result.append(name_status)
            status_result.append(password_status)
            if all(result == True for result in status_result):
                self.save_in_db(name, password)


            else:
                self.render("blog_signup.html", user_name=name, user_password="", user_email="",
                            name_status=name_status, password_status=password_status, email_status=email_status,
                            current_page="signUp")

    def save_in_db(self, userName, userPassword, email=None):
        userEmail = email
        encrypt_password = self.hash_it_with_salt(userName, userPassword)
        new_database_entry = User(user_name=userName, user_password=encrypt_password, user_email=userEmail)
        key = new_database_entry.put()
        hash = encrypt_password[0]
        self.set_cookie(hash, userName, key=key)
        self.redirect_to("AllPosts")

    def hash_it_with_salt(self, name, password):
        ##With a lil help from stackoverflow: http://stackoverflow.com/questions/2257441/random-string-generation-with-upper-case-letters-and-digits-in-python/23728630#23728630
        salt = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for x in xrange(10))
        hash = hashlib.sha512(name + password + salt).hexdigest()
        return [hash, salt]


class LogIn(Handler):
    ##TODO check bug when enter only whitespaces

    def get(self):
        cookie_value = self.request.cookies.get("name")
        template_name = "blog_login.html"
        if cookie_value is not None:
            valid_cookie = self.cookie_validator(cookie_value)
            # print valid_cookie
            if valid_cookie is not False:
                self.redirect_to("AllPosts")
            else:
                self.render(template_name, current_page="login")
                # print "bla"
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
                # print "non"
                self.render(template_name, current_page="login", error1="This username is not registered",
                            user_name=user_name, user_password=user_password)
            else:
                user = db.get(key)
                # print user.user_password
                user_saved_password = user.user_password
                user_hash = user_saved_password[0]
                user_salt = user_saved_password[1]
                last_hash = self.get_hash_with_salt(user_name, user_password, user_salt)
                # print last_hash
                hash_status = self.hash_validator(last_hash, key)
                # print hash_status
                if user_hash == last_hash:
                    self.set_cookie(user_hash, user_name)
                    self.redirect_to("AllPosts", current_page="logged_user")
                else:
                    self.render(template_name, current_page="login", error2="Incorrect Password", user_name=user_name,
                                user_password=user_password)


class NewPost(Handler):
    def get(self):
        # type: () -> object
        template_name = "blog_entry.html"
        cookie_value = self.request.cookies.get("name")
        # print cookie_value
        if cookie_value is not None and self.cookie_validator(cookie_value):
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
                user_name = self.cookie_validator(cookie_value)
                if user_name:
                    if title_status is True and content_status is True:
                        new_database_entry = Blog(title=blog_title, content=blog_content, user_name=user_name)
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
                        self.render(template_error, content=blog_content, error1=title_status,
                                    current_page="logged_user")
            else:
                self.redirect_to("Login")


class AllBlogPosts(Handler):
    def get(self):

        a = self.request

        cookie_value = self.request.cookies.get("name")
        posts = db.GqlQuery("SELECT * FROM Blog WHERE deletion_date = :deletion_date order by created desc limit 10",
                            deletion_date=None)
        template_name = "blog_posts.html"

        if cookie_value is not None and self.cookie_validator(cookie_value):
            print "cookie"
            user_name = self.cookie_validator(cookie_value)
            self.render(template_name, posts=posts, user=user_name, current_page="logged_user")
        else:
            print "non cookie"
            self.render(template_name, posts=posts, current_page="nonRegisteredUser")


class UserBlogPosts(Handler):
    def get(self):
        template_name = "blog_posts.html"
        cookie_value = self.request.cookies.get("name")

        if cookie_value is not None and self.cookie_validator(cookie_value):
            user_name = self.cookie_validator(cookie_value)
            user_posts = db.GqlQuery(
                "SELECT * FROM Blog WHERE user_name = :user_name and deletion_date = :deletion_date",
                user_name=user_name, deletion_date=None)
            self.render(template_name, posts=user_posts, current_page="logged_user")
        else:
            self.redirect_to("Login")

    def post(self):
        cookie_value = self.request.cookies.get("name")
        if cookie_value is not None and self.cookie_validator(cookie_value):
            post_number = self.request.POST.multi._items[0][0]
            q = Blog.get(post_number)
            bla = q.key().id()
            logged_user_name = self.cookie_validator(cookie_value)
            self.redirect_to("NewCreatedPost", blog_id=bla, user=logged_user_name)

        if self.request.POST.get("Edit"):
            # print "bla"
            self.redirect_to("Edit")
        elif self.request.POST.get("logout"):
            self.logout()


class SinglePost(Handler):
    def get(self, blog_id):
        # user like should return the button status like or liked

        cookie_value = self.request.cookies.get("name")
        if cookie_value is not None and self.cookie_validator(cookie_value):
            self.render_base(blog_id)
        else:
            cookie_value = self.request.cookies.get("name")
            # logged_user_name = self.cookie_checker(cookie_value)
            blog_key = db.Key.from_path("Blog", int(blog_id))

            blog = db.get(blog_key)

            ##user_like = self.give_key_like(blog_id, logged_user_name)
            blog_author = blog.user_name
            likes_counter = blog.likes
            # user_like = self.like_validator(blog_id, logged_user_name)


            comments = db.GqlQuery(
                "SELECT * FROM Comments WHERE blog_id = :blog_id and deletion_date = :deletion_date order by created desc",
                blog_id=blog_id, deletion_date=None)

            self.render("blog_redirect.html", post=blog, current_page="nonRegisteredUser",
                        user_name=None, likes=likes_counter,
                        blog_author=blog_author, comments=comments)

    def render_base(self, blog_id, current_comment="", deleted_comment=""):
        cookie_value = self.request.cookies.get("name")
        logged_user_name = self.cookie_validator(cookie_value)
        blog_key = db.Key.from_path("Blog", int(blog_id))

        blog = db.get(blog_key)
        blog = db.get(blog_key)

        user_like = self.like_validator(blog_id, logged_user_name)

        blog_author = blog.user_name
        likes_counter = blog.likes

        comments = db.GqlQuery(
            "SELECT * FROM Comments WHERE blog_id = :blog_id and deletion_date = :deletion_date order by created desc",
            blog_id=blog_id, deletion_date=None)

        self.render("blog_redirect.html", post=blog, current_page="logged_user",
                    user_name=logged_user_name, likes=likes_counter,
                    blog_author=blog_author, comments=comments, current_comment=current_comment, user_like=user_like,
                    deleted_comment=deleted_comment)

    def post(self, blog_id):
        # print "bla"
        key = db.Key.from_path("Blog", int(blog_id))
        post = db.get(key)
        # current_page = self.request.get("current_page")
        blog_title = self.request.get("title")
        blog_content = self.request.get("content")
        title_status = self.entry_validator("title", blog_title)
        content_status = self.entry_validator("content", blog_content)
        cookie_value = self.request.cookies.get("name")

        # for b in blass:
        #      print b
        if cookie_value is not None:
            user_name = self.cookie_validator(cookie_value)


        else:
            self.redirect_to("Login")

    # Render base
    # Checks if user has liked the post
    # Checks






    def give_key_like(self, blog_id, logged_user):

        query_likes = Likes.all(keys_only=True)
        query_likes.filter("blog_id", blog_id).filter("user_name", logged_user)
        key_likes = query_likes.get()
        # print "key"
        if key_likes == None:
            return True
        else:
            return False


class EditSinglePost(Handler):
    def get(self, blog_id):
        key = db.Key.from_path("Blog", int(blog_id))
        post = db.get(key)
        cookie_value = self.request.cookies.get("name")
        template_name = "blog_entry.html"

        if cookie_value is not None and self.cookie_validator(cookie_value):
            self.render(template_name, title=post.title, content=post.content, current_page="logged_user",
                        blog_id=blog_id, edit=True)

    def post(self, blog_id):
        # print "a"
        key = db.Key.from_path("Blog", int(blog_id))
        post = db.get(key)
        blog_title = self.request.get("title")
        blog_content = self.request.get("content")
        title_status = self.entry_validator("title", blog_title)
        content_status = self.entry_validator("content", blog_content)
        cookie_value = self.request.cookies.get("name")
        template_name = "blog_entry.html"

        if cookie_value is not None and self.cookie_validator(cookie_value):
            if self.request.POST.get("newPostButton"):
                if title_status is True and content_status is True:
                    # print "post NewPost"
                    post.title = blog_title
                    post.content = blog_content
                    post.put()
                    self.redirect_to("NewCreatedPost", blog_id=blog_id, current_page="logged_user")
                elif title_status is not True and content_status is not True:
                    user_error = title_status + ". " + content_status
                    self.render(template_name, error3=user_error, current_page="logged_user", blog_id=blog_id,
                                edit=True)
                elif title_status is True:
                    self.render(template_name, title=blog_title, error2=content_status, current_page="logged_user",
                                blog_id=blog_id, edit=True)
                else:
                    self.render(template_name, content=blog_content, error1=title_status, current_page="logged_user",
                                blog_id=blog_id, edit=True)


        else:
            self.redirect_to("Login")


class DeletePost(Handler):
    def post(self, blog_id):
        key_post = db.Key.from_path("Blog", int(blog_id))
        post = db.get(key_post)
        user_name = post.user_name
        cookie_value = self.request.cookies.get("name")
        template_name = "blog_posts.html"
        post_deletion_datetime = datetime.datetime.now()
        post.deletion_date = post_deletion_datetime
        post.put()

        if cookie_value is not None and self.cookie_validator(cookie_value):
            user_posts = db.GqlQuery("SELECT * FROM Blog WHERE user_name = :user_name and __key__ != :key_post",
                                     user_name=user_name, key_post=key_post)
            self.render(template_name, posts=user_posts, current_page="logged_user")


class LikePost(Handler):
    # instead of date liked or like
    def post(self, blog_id):
        cookie_value = self.request.cookies.get("name")
        key_post = db.Key.from_path("Blog", int(blog_id))
        post_entity = db.get(key_post)
        post_likes = post_entity.likes
        template_name = "blog_posts.html"

        if cookie_value is not None and self.cookie_validator(cookie_value):
            logged_user_name = self.cookie_validator(cookie_value)
            logged_user_key = self.get_key_by_user_name(logged_user_name)
            logged_user_entity = db.get(logged_user_key)

            query_likes = Likes.all(keys_only=True)
            query_likes.filter("blog_id", blog_id).filter("user_name", logged_user_name)
            query_likes_key = query_likes.get()

            if query_likes_key is None:

                like_entity = Likes(user_name=logged_user_name, blog_id=blog_id)
                like_entity.put()

                current_likes_count = post_entity.likes + 1
                post_entity.likes = current_likes_count
                post_entity.put()
                # self.render(template_name, user_like=False, likes=current_likes_count)
                self.redirect_to("NewCreatedPost", blog_id=blog_id)

                # self.render("blog_redirect.html", post=post_entity, current_page="logged_user",
                #             user_name=logged_user_name, likes=current_likes_count,
                #             blog_author=post_author)
            elif query_likes_key is not None:
                like_entity = db.get(query_likes_key)
                if like_entity.deletion_date is None:

                    current_likes_count = post_entity.likes - 1
                    post_entity.likes = current_likes_count
                    post_entity.put()
                    like_deletion_datetime = datetime.datetime.now()
                    like_entity.deletion_date = like_deletion_datetime
                    like_entity.put()
                    self.redirect_to("NewCreatedPost", blog_id=blog_id)
                else:
                    current_likes_count = post_entity.likes + 1
                    post_entity.likes = current_likes_count
                    post_entity.put()

                    like_entity.deletion_date = None
                    like_entity.put()
                    self.redirect_to("NewCreatedPost", blog_id=blog_id)
        else:
            self.redirect_to("Login")


class CommentPost(Handler):
    def post(self, blog_id):
        cookie_value = self.request.cookies.get("name")

        if cookie_value is not None and self.cookie_validator(cookie_value):
            logged_user_name = self.cookie_validator(cookie_value)
            user_comment = self.request.get("comment")

            comment_status = self.entry_validator("comment", user_comment)
            if comment_status is True:

                comment_entity = Comments(blog_id=blog_id, user_name=logged_user_name, comment=user_comment)
                comment_entity.put()
                self.redirect_to("NewCreatedPost", blog_id=blog_id)
            else:
                self.render_post(comment_error="Please add a valid comment", blog_id=blog_id,
                                 error="Please add a valid comment")
        else:
            self.redirect_to("Login")


class EditComment(Handler):
    def post(self, blog_id):

        request_str = self.request.body

        request_split = request_str.split("=")
        comment_id = request_split[0]
        action_clicked = request_split[1]
        #

        if action_clicked == "Edit":

            comment_key = db.Key.from_path("Comments", int(comment_id))
            comment_entity = db.get(comment_key)
            cookie_value = self.request.cookies.get("name")
            logged_user_name = self.cookie_validator(cookie_value)
            blog_key = db.Key.from_path("Blog", int(blog_id))
            blog = db.get(blog_key)
            blog = db.get(blog_key)
            user_like = self.like_validator(blog_id, logged_user_name)

            blog_author = blog.user_name
            likes_counter = blog.likes

            comments = db.GqlQuery("SELECT * FROM Comments WHERE blog_id = :blog_id order by created desc",
                                   blog_id=blog_id)

            self.render("blog_redirect.html", post=blog, current_page="logged_user",
                        user_name=logged_user_name, likes=likes_counter,
                        blog_author=blog_author, comments=comments, user_like=user_like, edit_comment=True,
                        comment_key=comment_key
                        )
        else:
            comment_id = self.request.POST.multi._items[1][0]
            comment_key = db.Key.from_path("Comments", int(comment_id))
            comment_entity = db.get(comment_key)
            modification_datetime = datetime.datetime.now()
            comment_entity.last_modified = modification_datetime
            current_comment = self.request.get("editComment")

            validation = self.entry_validator("title", current_comment)
            if validation is not True:
                cookie_value = self.request.cookies.get("name")
                logged_user_name = self.cookie_validator(cookie_value)
                blog_key = db.Key.from_path("Blog", int(blog_id))
                blog = db.get(blog_key)
                blog = db.get(blog_key)
                user_like = self.like_validator(blog_id, logged_user_name)

                blog_author = blog.user_name
                likes_counter = blog.likes

                comments = db.GqlQuery("SELECT * FROM Comments WHERE blog_id = :blog_id order by created desc",
                                       blog_id=blog_id)

                self.render("blog_redirect.html", post=blog, current_page="logged_user",
                            user_name=logged_user_name, likes=likes_counter,
                            blog_author=blog_author, comments=comments, user_like=user_like, edit_comment=True,
                            comment_key=comment_key,  error_comment= validation
                            )
            else:

                comment_entity.comment = current_comment
                comment_entity.put()
                self.redirect_to("NewCreatedPost", blog_id=blog_id)


class DeleteComment(Handler):
    def post(self, blog_id):
        request_str = self.request.body
        request_split = request_str.split("=")
        comment_id = request_split[0]
        comment_key = db.Key.from_path("Comments", int(comment_id))
        comment_entity = db.get(comment_key)
        deletion_datetime = datetime.datetime.now()
        comment_entity.deletion_date = deletion_datetime
        comment_entity.put()
        self.redirect_to("NewCreatedPost", blog_id=blog_id)


class UserProfile(Handler):
    # TODO add a cancel button on the changes form
    def get(self):
        cookie_value = self.request.cookies.get("name")
        if cookie_value is not None and self.cookie_validator(cookie_value):
            user_name = self.cookie_validator(cookie_value)
            key = self.get_key_by_user_name(user_name)
            user = db.get(key)
            user_email = user.user_email
            self.render("blog_my_profile.html", user_name=user_name, password="-----", email=user_email,
                        current_page="logged_user")
        else:
            self.redirect_to("Login")

    def post(self):
        cookie_value = self.request.cookies.get("name")
        user_name = self.cookie_validator(cookie_value)
        key = self.get_key_by_user_name(user_name)
        # print key
        user = db.get(key)
        user_hash_salt = user.user_password
        user_salt = user_hash_salt[1]
        user_saved_hash = user_hash_salt[0]
        user_email = user.user_email

        if self.request.POST.get("editName"):
            self.render("blog_my_profile.html", user_name=user_name, password="-----", email="", edit_name="yes",
                        current_page="logged_user")
        elif self.request.POST.get("editPassword"):
            self.render("blog_my_profile.html", user_name=user_name, password="-----", email="", edit_password="yes",
                        current_page="logged_user")
        elif self.request.POST.get("editEmail"):
            self.render("blog_my_profile.html", user_name=user_name, password="-----", email=user_email,
                        edit_email="yes", current_page="logged_user")
        # kindof
        if self.request.POST.get("saveName"):

            new_name = self.request.get("userName")
            name_status = self.name_validator(new_name)
            user_password = self.request.get("userPassword")
            entered_password_with_hash = self.get_hash_with_salt(user_name, user_password, user_salt)
            if name_status is True and entered_password_with_hash == user_saved_hash:
                new_hash_salt = self.hash_it_with_salt(new_name, user_password)
                new_hash = new_hash_salt[0]
                user.user_name = new_name
                user.user_password = new_hash_salt
                user.put()
                self.set_cookie(new_hash, new_name)
                self.render("blog_my_profile.html", user_name=new_name, password="-----", email="", edit_name="no",
                            current_page="logged_user")

                # change blog name
                blogs_by_user = db.GqlQuery("SELECT * FROM Blog WHERE user_name = :user_name ", user_name=user_name)

                for b in blogs_by_user:
                    b.user_name = new_name
                    b.put()
                    # print b.user_name

                comments_by_user = db.GqlQuery("SELECT * FROM Comments WHERE user_name = :user_name ",
                                               user_name=user_name)
                for c in comments_by_user:
                    c.user_name = new_name

                    b.put()

                likes_by_user = db.GqlQuery("SELECT * FROM Likes WHERE user_name = :user_name ",
                                            user_name=user_name)

                if likes_by_user != None:
                    for l in likes_by_user:
                        l.user_name = new_name
                        l.put()
                        # print l.user_name


                        # return user_key



            elif name_status is not True and entered_password_with_hash == user_saved_hash:
                # print "eror"
                self.render("blog_my_profile.html", user_name=user_name, password="-----", email="", error=name_status,
                            edit_name="yes", current_page="logged_user")
            elif name_status is True and entered_password_with_hash != user_saved_hash:
                self.render("blog_my_profile.html", user_name=user_name, password="-----", email="",
                            error="Please enter a valid password", edit_name="yes", current_page="logged_user")
            else:
                self.render("blog_my_profile.html", user_name=user_name, password="-----", email="",
                            error="Please enter a valid name and password", edit_name="yes", current_page="logged_user")

        elif self.request.POST.get("savePassword"):
            new_password = self.request.get("newPassword")
            new_password_confirmation = self.request.get("confirmNewPassword")
            user_password = self.request.get("currentUserPassword")
            entered_password_with_hash = self.get_hash_with_salt(user_name, user_password, user_salt)
            password_status = self.password_validator(new_password, new_password_confirmation)
            if password_status is True and entered_password_with_hash == user_saved_hash:
                new_saved_password = self.hash_it_with_salt(user_name, new_password)
                # print user_name

                new_hash = new_saved_password[0]
                # print new_saved_password
                user.user_password = new_saved_password
                user.put()
                self.set_cookie(new_hash, user_name)
                self.render("blog_my_profile.html", user_name=user_name, password="-----", email="", edit_password="no",
                            current_page="logged_user")
            elif password_status is not True and entered_password_with_hash == user_saved_hash:
                self.render("blog_my_profile.html", user_name=user_name, password="-----", email="",
                            error_password=password_status, edit_password="yes", current_page="logged_user")
            elif password_status is True and entered_password_with_hash != user_saved_hash:
                password_status = "Your current password is incorrect"
                self.render("blog_my_profile.html", user_name=user_name, password="-----", email="",
                            error_password=password_status, edit_password="yes", current_page="logged_user")
            else:
                password_status = password_status + " / Your current password is incorrect"
                self.render("blog_my_profile.html", user_name=user_name, password="-----", email="",
                            error_password=password_status, edit_password="yes", current_page="logged_user")

        elif self.request.POST.get("saveEmail"):
            new_email = self.request.get("newEmail")
            email_status = self.email_validator(new_email)

            if email_status is True:
                user.user_email = new_email
                user.put()
                self.render("blog_my_profile.html", user_name=user_name, password="-----", email=new_email,
                            edit_email="no")
            elif email_status is not True:
                self.render("blog_my_profile.html", user_name=user_name, password="-----", email=new_email,
                            error_email=email_status, edit_email="yes")


class LogOut(Handler):
    def get(self):
        self.response.delete_cookie("name")
        self.redirect_to("Login")


app = webapp2.WSGIApplication([webapp2.Route('/', handler=Handler, name='Home'),
                               webapp2.Route('/blog/blogposts', handler=AllBlogPosts, name='AllPosts'),
                               webapp2.Route('/blog/newpost', handler=NewPost, name='NewPost'),
                               webapp2.Route(r'/blog/<blog_id:[0-9]+>', handler=SinglePost, name='NewCreatedPost'),
                               webapp2.Route(r'/blog/edit/<blog_id:[0-9]+>', handler=EditSinglePost, name='Edit'),
                               webapp2.Route(r'/blog/delete/<blog_id:[0-9]+>', handler=DeletePost, name="DeletePost"),
                               webapp2.Route(r'/blog/like/<blog_id:[0-9]+>', handler=LikePost, name="LikePost"),
                               webapp2.Route(r'/blog/comment/<blog_id:[0-9]+>', handler=CommentPost,
                                             name="CommentPost"),
                               webapp2.Route(r'/blog/edit-comment/<blog_id:[0-9]+>', handler=EditComment,
                                             name="EditComment"),
                               webapp2.Route(r'/blog/delete-comment/<blog_id:[0-9]+>', handler=DeleteComment,
                                             name="DeleteComment"),
                               webapp2.Route('/blog/signup', handler=SignUp, name='SignUp'),
                               webapp2.Route('/blog/login', handler=LogIn, name='Login'),
                               webapp2.Route('/blog/myposts', handler=UserBlogPosts, name="UserPosts"),
                               webapp2.Route('/blog/myprofile', handler=UserProfile, name="UserProfile"),
                               webapp2.Route('/blog/logout', handler=LogOut, name="LogOut"),

                               ],
                              debug=True)
