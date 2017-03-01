
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