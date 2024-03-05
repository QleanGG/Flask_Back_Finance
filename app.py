from flask import Flask, request, jsonify
import yfinance as yf
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import desc
from sqlalchemy.orm import relationship
from flask_login import LoginManager, login_user, current_user, logout_user, login_required
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
CORS(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///yourdatabase.db'  
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key_here'  # Change to your secret key
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key_here'  # Change to your JWT secret key

db = SQLAlchemy(app)
login_manager = LoginManager(app)
jwt = JWTManager(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    search_history = db.relationship('SearchHistory', back_populates='user')


    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class SearchHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    query_text = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = relationship("User", back_populates="search_history")

with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/get_stock',methods=['POST'])
def get_stock():
    try:
        data = request.json
        print(data)
        ticker_symbol = data.get('ticker')

        if ticker_symbol is None:
        # Respond with an error if 'ticker' is not provided
            return jsonify({"error": "Ticker symbol is required."}), 400

        stock = yf.Ticker(ticker_symbol)


        info = stock.info
        extended_info = {
            "ticker": ticker_symbol,
            "companyName": info.get('longName', 'Unknown Company'),
            "currentPrice": info.get('currentPrice'),
            "marketCap": info.get('marketCap'),
            "forwardPE": info.get('forwardPE'),
            "dividendYield": info.get('dividendYield', 0) *100,
            "fiftyTwoWeekHigh": info.get('fiftyTwoWeekHigh'),
            "fiftyTwoWeekLow": info.get('fiftyTwoWeekLow'),
            "volume": info.get('volume'),
        }

        # Fetching historical data
        periods = ["1d", "1wk", "1mo", "1y"]
        historical_data = {}
        for period in periods:
            hist = stock.history(period=period)
            # Convert DataFrame to records and then to list of dicts
            historical_data[period] = hist.to_dict('records')

        extended_info["historicalData"] = historical_data


        return jsonify(extended_info)
    except Exception as e:
        return jsonify({"error": str(e)})


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    user = User(username=data['username'], email=data['email'])
    user.set_password(data['password'])
    db.session.add(user)
    db.session.commit()
    return jsonify({"message": "User registered successfully"}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    if user and user.check_password(data['password']):
        access_token = create_access_token(identity={"username": data['username'], "user_id": user.id})
        print(access_token)
        return jsonify({"message": "Logged in successfully", "access_token": access_token})
    return jsonify({"message": "Invalid username or password"}), 401

@app.route('/watch_history', methods=['GET','POST'])
@jwt_required()
def watch_history():
    if request.method == 'GET':
        user_identity = get_jwt_identity()
        user_id = user_identity.get('user_id')

        if user_id is None:
            return jsonify({"message": "Invalid token format"}), 400

        user = User.query.get(user_id)

        if user is None:
            return jsonify({"message": "User not found"}), 404

        # Retrieve search history for the user
        history = SearchHistory.query.filter(SearchHistory.user_id == user_id) \
                                     .order_by(SearchHistory.id.desc()) \
                                     .limit(10) \
                                     .all()

        response = []
        for item in history:
            # Fetch company info using yfinance
            stock = yf.Ticker(item.query_text)
            info = stock.info

            response.append({
                "query_text": item.query_text,
                "companyName": info.get('longName', 'Unknown Company'),
                "currentPrice": info.get('currentPrice'),
            })

        return jsonify(response)

    
    elif request.method == 'POST':
        print('we here!')
        data = request.json
        query = data.get('query')
        if query:
            user_identity = get_jwt_identity()
            user_id = user_identity.get('user_id')
            search_history_entry = SearchHistory(query_text=query, user_id=user_id)
            db.session.add(search_history_entry)
            db.session.commit()
            return jsonify({"message":"Added to search history"}), 201
        return jsonify({"error": "Query parameter is required"}), 400
    

if __name__ == "__main__":
    app.run(debug=True)