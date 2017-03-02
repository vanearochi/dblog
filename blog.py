
import webapp2

from handlers.handlers import SignUp, LogIn, NewPost, AllBlogPosts, UserBlogPosts, SinglePost, EditSinglePost, \
    DeletePost, LikePost, CommentPost, EditComment, DeleteComment, UserProfile, LogOut


app = webapp2.WSGIApplication([webapp2.Route('/', handler=AllBlogPosts, name='Home'),
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
