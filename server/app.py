from flask import Flask, request, session, make_response
from flask_migrate import Migrate
from flask_restful import Api, Resource
from flask_cors import CORS
from models import db, User, Recipe

app = Flask(__name__)
# The secret key is what encrypts the session cookie
app.secret_key = b'\x15\xba\x8b\xce\xc1\x14\x8e\xf6' 
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.json.compact = False

CORS(app)
migrate = Migrate(app, db)
db.init_app(app)

api = Api(app)

# --- AUTHENTICATION RESOURCES ---

class Signup(Resource):
    def post(self):
        data = request.get_json()
        try:
            # Create user and hash password via the @hybrid_property setter
            user = User(
                username=data.get('username'),
                image_url=data.get('image_url'),
                bio=data.get('bio')
            )
            user.password_hash = data.get('password')
            db.session.add(user)
            db.session.commit()
            # Log them in automatically
            session['user_id'] = user.id
            return make_response(user.to_dict(), 201)
        except Exception as e:
            return make_response({"errors": [str(e)]}, 422)

class CheckSession(Resource):
    def get(self):
        # Auto-login: Check if user_id is in the "cookie"
        user_id = session.get('user_id')
        if user_id:
            user = User.query.filter(User.id == user_id).first()
            return make_response(user.to_dict(), 200)
        return make_response({"error": "Unauthorized"}, 401)

class Login(Resource):
    def post(self):
        data = request.get_json()
        user = User.query.filter(User.username == data.get('username')).first()
        # use the authenticate method we wrote in models.py
        if user and user.authenticate(data.get('password')):
            session['user_id'] = user.id
            return make_response(user.to_dict(), 200)
        return make_response({"error": "Invalid username or password"}, 401)

class Logout(Resource):
    def delete(self):
        if session.get('user_id'):
            session['user_id'] = None
            return make_response({}, 204)
        return make_response({"error": "Unauthorized"}, 401)

# --- RECIPE RESOURCES (Authorized Only) ---

class RecipeIndex(Resource):
    def get(self):
        if session.get('user_id'):
            recipes = [r.to_dict() for r in Recipe.query.all()]
            return make_response(recipes, 200)
        return make_response({"error": "Unauthorized"}, 401)

    def post(self):
        user_id = session.get('user_id')
        if user_id:
            data = request.get_json()
            try:
                recipe = Recipe(
                    title=data.get('title'),
                    instructions=data.get('instructions'),
                    minutes_to_complete=data.get('minutes_to_complete'),
                    user_id=user_id
                )
                db.session.add(recipe)
                db.session.commit()
                return make_response(recipe.to_dict(), 201)
            except Exception as e:
                return make_response({"errors": [str(e)]}, 422)
        return make_response({"error": "Unauthorized"}, 401)

api.add_resource(Signup, '/signup')
api.add_resource(CheckSession, '/check_session')
api.add_resource(Login, '/login')
api.add_resource(Logout, '/logout')
api.add_resource(RecipeIndex, '/recipes')

if __name__ == '__main__':
    app.run(port=5555, debug=True)