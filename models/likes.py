
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