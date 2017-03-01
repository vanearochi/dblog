
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