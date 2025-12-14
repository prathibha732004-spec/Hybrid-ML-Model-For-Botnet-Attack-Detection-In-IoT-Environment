from flask import Flask,render_template,redirect,request
app = Flask(__name__)
import pandas as pd 
import tensorflow as tf
import joblib
import pandas as pd
from sklearn.preprocessing import LabelEncoder
from sklearn.feature_selection import SelectKBest, chi2
import numpy as np

import os
import mysql.connector
mydb = mysql.connector.connect(
    host=os.getenv("DB_HOST"),
    user=os.getenv("DB_USER"),
    password=os.getenv("DB_PASSWORD"),
    database=os.getenv("DB_NAME"),
    port=int(os.getenv("DB_PORT"))
)



mycur = mydb.cursor()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/registration', methods=['POST', 'GET'])
def registration():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        confirmpassword = request.form['confirmpassword']
        address = request.form['Address']
        
        if password == confirmpassword:
            # Check if user already exists
            sql = 'SELECT * FROM users WHERE email = %s'
            val = (email,)
            mycur.execute(sql, val)
            data = mycur.fetchone()
            if data is not None:
                msg = 'User already registered!'
                return render_template('registration.html', msg=msg)
            else:
                # Insert new user without hashing password
                sql = 'INSERT INTO users (name, email, password, Address) VALUES (%s, %s, %s, %s)'
                val = (name, email, password, address)
                mycur.execute(sql, val)
                mydb.commit()
                
                msg = 'User registered successfully!'
                return render_template('registration.html', msg=msg)
        else:
            msg = 'Passwords do not match!'
            return render_template('registration.html', msg=msg)
    return render_template('registration.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        sql = 'SELECT * FROM users WHERE email=%s'
        val = (email,)
        mycur.execute(sql, val)
        data = mycur.fetchone()

        if data:
            stored_password = data[3]  
            # Check if the password matches the stored password
            if password == stored_password:
                return redirect('/viewdata')
            else:
                msg = 'Password does not match!'
                return render_template('login.html', msg=msg)
        else:
            msg = 'User with this email does not exist. Please register.'
            return render_template('login.html', msg=msg)
    return render_template('login.html')

@app.route('/viewdata')
def viewdata():
    # Load the dataset
    df = pd.read_csv('UNSW_NB15.csv')
    df = df.head(1000)

    table_html = df.to_html(classes='table table-striped table-hover', index=False)
    return render_template('viewdata.html', table=table_html)


# Load models
ann_model = tf.keras.models.load_model('saved models/ann_model.h5')
cnn_model = tf.keras.models.load_model('saved models/cnn_model.h5')
rnn_model = tf.keras.models.load_model('saved models/rnn_model.h5')
lstm_model = tf.keras.models.load_model('saved models/lstm_model.h5')
rf_model = joblib.load('saved models/random_forest_model.pkl')

# Load the dataset
data = pd.read_csv('UNSW_NB15.csv')
data_cleaned = data.drop(columns=['id', 'label'])
label_encoder = LabelEncoder()
data_cleaned['attack_cat_encoded'] = label_encoder.fit_transform(data_cleaned['attack_cat'])
data_cleaned = data_cleaned.drop(columns=['attack_cat'])

# Encode categorical columns
categorical_columns = ['proto', 'service', 'state']
for column in categorical_columns:
    data_cleaned[column] = label_encoder.fit_transform(data_cleaned[column])

X = data_cleaned.drop(columns=['attack_cat_encoded'])
y = data_cleaned['attack_cat_encoded']

# Feature selection
k_best_selector = SelectKBest(score_func=chi2, k=10)
X_new = k_best_selector.fit_transform(X, y)
selected_features = X.columns[k_best_selector.get_support(indices=True)]
X_selected = data_cleaned[selected_features]
print(X_selected.columns)

# Split the data
from sklearn.model_selection import train_test_split
X_train, X_test, y_train, y_test = train_test_split(X_selected, y, test_size=0.2, random_state=42)

def evaluate_model(model_name):
    if model_name == 'ANN':
        model = ann_model
    elif model_name == 'CNN':
        model = cnn_model
    elif model_name == 'RNN':
        model = rnn_model
    elif model_name == 'LSTM':
        model = lstm_model
    elif model_name == 'RandomForest':
        model = rf_model
    else:
        return "Invalid model name"

    if model_name in ['ANN', 'CNN', 'RNN', 'LSTM']:
        y_pred = model.predict(X_test).argmax(axis=1)
    else:
        y_pred = model.predict(X_test)
    
    from sklearn.metrics import classification_report
    report = classification_report(y_test, y_pred, output_dict=True)
    accuracy = report['accuracy']
    return accuracy

@app.route('/algo', methods=['GET', 'POST'])
def algo():
    model_name = request.form.get('model', 'ANN')
    accuracy = evaluate_model(model_name)
    return render_template('algo.html', accuracy=accuracy, model_name=model_name)


# Load the saved model
rf_model = joblib.load('saved models/random_forest_model.pkl')

# Dictionary mapping encoded values to attack categories
attack_cat_mapping = {
    0: 'Analysis',
    1: 'Backdoor',
    2: 'DoS',
    3: 'Exploits',
    4: 'Fuzzers',
    5: 'Generic',
    6: 'Normal',
    7: 'Reconnaissance',
    8: 'Shellcode',
    9: 'Worms'
}


@app.route('/prediction', methods=['GET', 'POST'])
def prediction():
    if request.method == 'POST':
        try:
            # Extract input data from the form
            input_data = [
                float(request.form['sbytes']),
                float(request.form['dbytes']),
                float(request.form['rate']),
                float(request.form['sload']),
                float(request.form['dload']),
                float(request.form['sinpkt']),
                float(request.form['sjit']),
                float(request.form['stcpb']),
                float(request.form['dtcpb']),
                float(request.form['response_body_len'])
            ]
            
            input_data = np.array([input_data])
            
            # Make prediction
            predicted_attack_idx = rf_model.predict(input_data)[0]
            predicted_attack_category = attack_cat_mapping[predicted_attack_idx]
            print(predicted_attack_category)
            return render_template('prediction.html', msg=f'Predicted Attack Category: {predicted_attack_category}')
        except Exception as e:
            return render_template('prediction.html', msg=f'Error: {str(e)}')
    return render_template('prediction.html')


if __name__ == '__main__':
    app.run(debug=True)