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
        """Checks if the cookie name passed is valid.
                Searchs for the user name and hash and compare them with the cookie values.
        Args:
            cookie_name: String representing the cookie's name that is formed by the user_name and his created hash_value.
        Returns:
            A string representing the user name when the cookie is valid and False if is not .
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
        """Checks if the hash value passed is the same as the one stored for a particular key object.
        Args:
            hash_value: String representing the hash stored at the current user's cookie.
            user_key: Key object assigned to a particular instance.
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
        Entry could be a title, comment or content, they differ in length and they should not be only white spaces.
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

    def name_validator(self, user_name):
        """Checks if the user name is has a valid name and is not only white spaces.
        Args:
            user_name: string representing the name the user is trying to register.
        Returns:
            A string indicating an error or a boolean value if the name is valid.
        """
        error_name = "Please enter a valid name"
        user_no_spaces = user_name.replace(" ", "")
        if all(result != " " for result in user_no_spaces):
            if 3 <= len(user_no_spaces) < 25:
                return self.db_search(user_no_spaces)
            else:
                return error_name
        else:
            return error_name

    def db_search(self, user_name):
        """Search in database for the name that the user is trying to register.
        Args:
            user_name: string representing the name the user is trying to register.
        Returns:
            A boolean value if the name doesn't exist in the database and an error if it does.
        """
        query = User.all(keys_only=True)
        query.filter("user_name =", user_name)
        error_name_database = "This name is already in use, please enter a new one"
        key = query.get()
        if key == None:
            return True
        else:
            return error_name_database

    def hash_it_with_salt(self, user_name, user_password):
        """Creates a salt string and hashed it with user name and password entered.
        Args:
            user_name: String representing the name that the user is registering.
            user_password: String representing the password entered.
        Returns:
            A hash value and the salt created for a particular user.
        """
        # With a lil help from stackoverflow:
        # http://stackoverflow.com/questions/2257441/
        # random-string-generation-with-upper-case-letters-and-digits-in-python/23728630#23728630
        salt = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for x in xrange(10))

        hash = hashlib.sha512(user_name + user_password + salt).hexdigest()
        return [hash, salt]

    def set_cookie(self, user_hash, user_name, key=None):
        """Concatenates arguments to create a cookie value and sets it.
        Args:
            user_hash: String representing the hash value for a particular user.
            user_name: String representing the name that the user registered.
            key: Key object assigned to a particular instance.
        """
        value = user_name + "|" + user_hash
        if key is not None:
            value += "|" + str(key)

        self.response.set_cookie("name", value)

    def password_validator(self, user_password, password_confirmation):
        """Checks if password entered meets a min length and match with the confirmation.
        Args:
            user_password: String representing the password entered.
            password_confirmation: String representing the password entered.
        Returns:
            An error if password is not valid and a boolean value if it is valid.
        """
        error_valid_password = "Please enter a valid password"
        error_match_password = "Passwords entered don't match"
        if all(result != " " for result in user_password):
            if 6 < len(user_password) < 20:
                if user_password == password_confirmation:
                    return True
                else:
                    return error_match_password
        return error_valid_password

    def email_validator(self, user_email):
        """Checks if email entered has or not certain characters.
            Notice that there is an email checkup performed by Bootstrap too.
        Args:
            user_email: String representing the email entered by the user.
        Returns:
            A boolean value if the email is valid and an error if is not.
        """
        error_valid_email = "Please enter a valid email"
        if user_email.find(' ') == -1 and user_email.find("@") != -1:
            if user_email.find('.') != -1:
                return True
        return error_valid_email

    def like_validator(self, post_id, user_name):
        """Checks if user has liked or not a particular blog post.
        Args:
            post_id: A string representing the id of a created blog_post.
            user_name: A string representing the name of the user logged in.
        Returns:
            A string indicating if user likes or not the post.
        """
        query_likes = Likes.all(keys_only=True)
        query_likes.filter("blog_id", post_id).filter("user_name", user_name)
        key_likes = query_likes.get()

        if key_likes is None:
            return "Like"
        else:
            like_entity = db.get(key_likes)
            if like_entity.deletion_date is None:
                return "Liked"
            else:
                return "Like"

    def render_post(self, comment_error=None, blog_id=None, error=None, comment_key=None, edit_comment=None):
        """"""
        comment_error = comment_error
        cookie_value = self.request.cookies.get("name")
        blog_key = db.Key.from_path("Blog", int(blog_id))
        blog = db.get(blog_key)
        likes_counter = blog.likes
        blog_author = blog.user_name
        comments = db.GqlQuery(
            "SELECT * FROM Comments WHERE blog_id = :blog_id and deletion_date = :deletion_date order by created desc",
            blog_id=blog_id, deletion_date=None)

        if cookie_value is not None and self.cookie_validator(cookie_value):
            logged_user_name = self.cookie_validator(cookie_value)
            user_like = self.like_validator(blog_id, logged_user_name)
            self.render("blog_redirect.html", post=blog, current_page="logged_user",
                        user_name=logged_user_name, likes=likes_counter,
                        blog_author=blog_author, comments=comments, user_like=user_like, comment_error=comment_error,
                        error=error, comment_key=comment_key, edit_comment=edit_comment)
        else:
            logged_user_name = None
            self.render("blog_redirect.html", post=blog, current_page="nonRegisteredUser",
                        user_name=logged_user_name, likes=likes_counter,
                        blog_author=blog_author, comments=comments, comment_error=comment_error,
                        error=error)


class SignUp(Handler):
    """Handles Sign up form requests"""

    def get(self):
        """Renders signup template if there is not a session initiated or if the cookie is not longer valid.
           If the current session is valid then redirect to All posts page
         """
        cookie_value = self.request.cookies.get("name")
        template_name = "blog_signup.html"
        if cookie_value is not None:
            valid_cookie = self.cookie_validator(cookie_value)
            if valid_cookie is not False:
                self.redirect_to("AllPosts")
            else:
                self.render(template_name, current_page="signUp")
        else:
            self.render(template_name, user_name="", user_password="", user_email="", current_page="signUp")

    def post(self):
        """Sends to check if the information entered by the user when registering is valid,
            if it is then initialize a session calling functions to save the information and set the cookie and
            redirecting to all posts page. Otherwise, it renders again the sign up page
            with the corresponding errors.
        """
        user_name = self.request.get("userName")
        user_password = self.request.get("userPassword")
        user_password_confirmation = self.request.get("passwordConfirmation")
        user_email = self.request.get("userEmail")
        name_status = self.name_validator(user_name)
        password_status = self.password_validator(user_password, user_password_confirmation)
        status_result = []
        email_status = ""
        if len(user_email) > 0 and user_email.isspace() is not True:
            email_status = self.email_validator(user_email)
            status_result.append(name_status)
            status_result.append(password_status)
            status_result.append(email_status)
            if all(result is True for result in status_result):
                self.save_in_db(user_name, user_password, user_email)
                self.redirect_to("AllPosts")
            else:
                self.render("blog_signup.html", user_name=user_name, user_password="", user_email=user_email,
                            name_status=name_status, password_status=password_status, email_status=email_status,
                            current_page="signUp")
        else:
            status_result.append(name_status)
            status_result.append(password_status)
            if all(result is True for result in status_result):
                self.save_in_db(user_name, user_password)
                self.redirect_to("AllPosts")
            else:
                self.render("blog_signup.html", user_name=user_name, user_password="", user_email="",
                            name_status=name_status, password_status=password_status, email_status=email_status,
                            current_page="signUp")

    def save_in_db(self, user_name, user_password, email=None):
        """Creates an an entity of User kind, saves it and set the cookie"""
        user_email = email
        encrypt_password = self.hash_it_with_salt(user_name, user_password)
        new_database_entry = User(user_name=user_name, user_password=encrypt_password, user_email=user_email)
        key = new_database_entry.put()
        user_hash = encrypt_password[0]
        self.set_cookie(user_hash, user_name, key=key)


class LogIn(Handler):
    """Handles Login requests"""

    def get(self):
        """Renders login template if there is not a session initiated or if the cookie is not longer valid.
           If the current session is valid then redirect to All posts page
        """
        cookie_value = self.request.cookies.get("name")
        template_name = "blog_login.html"
        if cookie_value is not None:
            valid_cookie = self.cookie_validator(cookie_value)
            if valid_cookie is not False:
                self.redirect_to("AllPosts")
            else:
                self.render(template_name, current_page="login")
        else:
            self.render(template_name, current_page="login")

    def post(self):
        """Sends to check if the information entered by the user when login in is valid,
           if it is then initialize a session setting the corresponding cookie.
           Otherwise, it renders again the log in page with the corresponding errors.
        """
        user_name = self.request.get("name")
        # With a lil help from stackoverflow:
        # http://stackoverflow.com/questions/21505255/identify-which-submit-button-was-clicked-in-django-form-submit
        user_password = self.request.get("password")
        template_name = "blog_login.html"
        if all(result != " " for result in user_name) and len(user_name) > 0:
            key = self.get_key_by_user_name(user_name)
            if key is None:
                self.render(template_name, current_page="login", error1="This username is not registered",
                            user_name=user_name, user_password=user_password)
            else:
                user_entity = db.get(key)
                user_saved_password = user_entity.user_password
                user_hash = user_saved_password[0]
                user_salt = user_saved_password[1]
                last_hash = self.get_hash_with_salt(user_name, user_password, user_salt)
                hash_status = self.hash_validator(last_hash, key)
                if hash_status is True:
                    self.set_cookie(user_hash, user_name)
                    self.redirect_to("AllPosts", current_page="logged_user")
                else:
                    self.render(template_name, current_page="login", error2="Incorrect Password", user_name=user_name,
                                user_password=user_password)
        else:
            self.render(template_name, current_page="login", error1="Please enter a valid user name",
                        user_name=user_name, user_password=user_password)


class NewPost(Handler):
    """Handles New Post request"""

    def get(self):
        """Renders new post template with different navigation bar depending on the status of the user's session"""
        template_name = "blog_entry.html"
        cookie_value = self.request.cookies.get("name")
        if cookie_value is not None and self.cookie_validator(cookie_value):
            self.render(template_name, title="", content="", current_page="logged_user")
        else:
            self.render(template_name, title="", content="", current_page="nonRegisteredUser")

    def post(self):
        """Verify if the user has an active session, if valid, then sends to check the post that the user
           is trying to submit, if valid, creates a new blog entity of Blog kind and saves it.
           If the info is not valid it renders the blog entry again with the corresponding error.
           If the session is not valid redirects to login """
        template_error = "blog_entry.html"
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
    """Handles all post requests"""

    def get(self):
        """Renders all posts template with different navigation bar
        depending on the status of the user's session"""

        cookie_value = self.request.cookies.get("name")
        posts = db.GqlQuery("SELECT * FROM Blog WHERE deletion_date = :deletion_date order by created desc limit 10",
                            deletion_date=None)
        template_name = "blog_posts.html"
        if cookie_value is not None and self.cookie_validator(cookie_value):
            user_name = self.cookie_validator(cookie_value)
            self.render(template_name, posts=posts, user=user_name, current_page="logged_user")
        else:
            self.render(template_name, posts=posts, current_page="nonRegisteredUser")


class UserBlogPosts(Handler):
    """Handles User blog requests"""

    def get(self):
        """Renders user posts template if there is an active session if not then redirects to Login"""
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


class SinglePost(Handler):
    """Calls a function that renders redirect template with different navigation bar
            depending on the status of the user's session"""

    def get(self, blog_id):
        self.render_post(blog_id=blog_id)


class EditSinglePost(Handler):
    """Handles Edit requests"""

    def get(self, blog_id):
        """Renders blog entry template filed with the post to be modified"""
        key = db.Key.from_path("Blog", int(blog_id))
        post = db.get(key)
        cookie_value = self.request.cookies.get("name")
        template_name = "blog_entry.html"
        if cookie_value is not None and self.cookie_validator(cookie_value):
            self.render(template_name, title=post.title, content=post.content, current_page="logged_user",
                        blog_id=blog_id, edit=True)

    def post(self, blog_id):
        """ Verify if the user has an active session, if valid, then sends to check the post that the user
           is trying to submit, if valid, searchs for the post entity abnd save the changes.
           If the info is not valid it renders the blog entry again with the corresponding error.
           If the session is no longer valid redirects to login. """

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
    """ Handles delete post requests"""

    def post(self, blog_id):
        """Verifies if user's session is still valid and
        Soft deletes user's post modifying the deletion date on the post entity"""
        cookie_value = self.request.cookies.get("name")
        if cookie_value is not None and self.cookie_validator(cookie_value):
            key_post = db.Key.from_path("Blog", int(blog_id))
            post = db.get(key_post)
            post_deletion_datetime = datetime.datetime.now()
            post.deletion_date = post_deletion_datetime
            post.put()
            self.redirect_to("AllPosts")


class LikePost(Handler):
    """Handles like post requests"""
    def post(self, blog_id):
        """Verifies if user's session is still valid and if the user has already liked the post
           if not liked then creates a new entity of kind like, after that the like status depend on the deletion date.
           The like counter on the blog entity changes accordingly.
        """
        cookie_value = self.request.cookies.get("name")
        key_post = db.Key.from_path("Blog", int(blog_id))
        post_entity = db.get(key_post)

        if cookie_value is not None and self.cookie_validator(cookie_value):
            logged_user_name = self.cookie_validator(cookie_value)
            query_likes = Likes.all(keys_only=True)
            query_likes.filter("blog_id", blog_id).filter("user_name", logged_user_name)
            query_likes_key = query_likes.get()
            if query_likes_key is None:
                like_entity = Likes(user_name=logged_user_name, blog_id=blog_id)
                like_entity.put()
                current_likes_count = post_entity.likes + 1
                post_entity.likes = current_likes_count
                post_entity.put()
                self.redirect_to("NewCreatedPost", blog_id=blog_id)
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
    """Handles comment post requests"""
    def post(self, blog_id):
        """Verifies if user's session is still valid, if valid, verifies the comment submitted,
         if creates a new comment entity of kind comment and saves it.
         If not valid renders the same template with corresponding errors
         Beware that there will be a small inconsistency when submitting so it might appear after
         reloading """

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
    """Handles edit comment requests"""

    def post(self, blog_id):
        """Verifies if user's session is still valid, if valid, verifies the comment submitted,
         if creates a new comment entity of kind comment and saves it.
         If not valid renders the same template with corresponding errors
         Beware that there will be a small inconsistency when saving the change so it might appear after
         reloading"""

        cookie_value = self.request.cookies.get("name")
        if cookie_value is not None and self.cookie_validator(cookie_value):
            request_str = self.request.body
            request_split = request_str.split("=")
            comment_id = request_split[0]
            action_clicked = request_split[1]
            if action_clicked == "Edit":
                comment_key = db.Key.from_path("Comments", int(comment_id))
                self.render_post(blog_id=blog_id, comment_key=comment_key, edit_comment=True)
            else:
                comment_id = self.request.POST.multi._items[1][0]
                comment_key = db.Key.from_path("Comments", int(comment_id))
                comment_entity = db.get(comment_key)
                modification_datetime = datetime.datetime.now()
                comment_entity.last_modified = modification_datetime
                current_comment = self.request.get("editComment")
                validation = self.entry_validator("title", current_comment)
                if validation is not True:
                    self.render_post(comment_key=comment_key, edit_comment=True, blog_id=blog_id,
                                     current_comment=current_comment)
                else:
                    comment_entity.comment = current_comment
                    comment_entity.put()
                    self.redirect_to("NewCreatedPost", blog_id=blog_id)
        else:
            self.redirect.to("Login")


class DeleteComment(Handler):
    """Handles Delete comment requests"""
    def post(self, blog_id):
        """Verifies if user's session is still valid and
            if it is, it soft deletes user's post modifying the deletion date on the comment entity"""
        cookie_value = self.request.cookies.get("name")
        if cookie_value is not None and self.cookie_validator(cookie_value):
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
    """Handles my profile requests"""

    def get(self):
        """Verifies if user's session is still valid and
          renders my profile template."""
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
        """Verifies which button was clicked  and render the same page with an input field
        then  if user's session is still valid and user save changes:
        -For user's name change the info in every entity using it and sets the cookie again.
        -For password changes the info in User entity and set the cookie again.
        -For email changes info in User entity"""
        cookie_value = self.request.cookies.get("name")
        user_name = self.cookie_validator(cookie_value)
        key = self.get_key_by_user_name(user_name)
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
                blogs_by_user = db.GqlQuery("SELECT * FROM Blog WHERE user_name = :user_name ", user_name=user_name)
                for blog in blogs_by_user:
                    blog.user_name = new_name
                    blog.put()

                comments_by_user = db.GqlQuery("SELECT * FROM Comments WHERE user_name = :user_name ",
                                               user_name=user_name)
                for comment in comments_by_user:
                    comment.user_name = new_name
                    comment.put()

                likes_by_user = db.GqlQuery("SELECT * FROM Likes WHERE user_name = :user_name ",
                                            user_name=user_name)
                if likes_by_user is not None:
                    for l in likes_by_user:
                        l.user_name = new_name
                        l.put()

            elif name_status is not True and entered_password_with_hash == user_saved_hash:
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
                new_hash = new_saved_password[0]
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
                password_status += " / Your current password is incorrect"
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
    """Handles log out requests"""
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
