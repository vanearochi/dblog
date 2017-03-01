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