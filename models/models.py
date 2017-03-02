from google.appengine.ext import db


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


class Blog(db.Model):
    """Blog database model
    Attributes:
        user: An instance object representing a unique user's key
        title: A string representing the blog title
        content: A string representing the blog content
        like: A list that contains the users that liked
        created: An integer representation of the date and time of blog's creation.
        show_created: An integer representation of the blog's date creation that will be displayed
        last_modified: An integer representation of the date and time of the last time the blog was modified, if any.
        deletion_date: An integer representation of the date and time of blog's deletion, helps with soft deletion.
    """
    user = db.ReferenceProperty(User, collection_name="posts")
    title = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    like = db.ListProperty(db.Key, default=None)
    created = db.DateTimeProperty(auto_now_add=True)
    show_created = db.DateProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty()
    deletion_date = db.DateTimeProperty(default=None)


class Comments(db.Model):
    """Comments database Model:
    Attributes:
        blog_id: String representation of the id of the blog commented.
        created: An integer representation of the date and time of the comment's creation.
        last_modified: An integer representation of the date and time of the last time the commented was modified.
        deletion_date: An integer representation of the date and time that user delete the comment.
        user_comment: An instance object representing a unique user's key.
        """
    comment = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty()
    deletion_date = db.DateTimeProperty(default=None)
    user_commenter = db.ReferenceProperty(User, required=True, collection_name="commenter")
    post_commented = db.ReferenceProperty(Blog, required=True, collection_name="commented")