from flask import Flask, render_template, url_for, redirect, session, request
from rdflib import Graph
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'samplesecretkey'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    user_type = db.Column(db.String(80), nullable=False)


class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired()], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired()], render_kw={"placeholder": "Password"})
    user_type = StringField(validators=[InputRequired()], render_kw={"placeholder": "User Type"})
    submit = SubmitField('Register')


class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired()], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired()], render_kw={"placeholder": "Password"})
    user_type = StringField(validators=[InputRequired()], render_kw={"placeholder": "User Type"})
    submit = SubmitField('Login')

@app.route('/')
def home():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                if user.user_type == "ADMIN":
                    return render_template('admin.html')
                else:
                    session['username'] = request.form['username']
                    return render_template('worker.html')
    return render_template('login.html', form=form)


@ app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password, user_type=form.user_type.data)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@ app.route('/admin', methods=['GET', 'POST'])
def admin():
    return render_template('admin.html')

@ app.route('/admin-table/', methods=['GET', 'POST'])
def admin_table():
    g = Graph()
    g.parse("RDFFile.rdf")
    col1data = []
    col2data = []
    if request.form['submit_button'] == 'current location':
        knows_query = """
            SELECT ?x ?y
            WHERE {
                ?x <http://www.semanticweb.org/win11/ontologies/2023/4/untitled-ontology-21#currentLocation> ?y
            }
        """
        qres = g.query(knows_query)
        for row in qres:
            col1 = str(row.x)
            col2 = str(row.y)
            col1data.append(col1[72:])
            col2data.append(col2[72:])
        return render_template('admin-table.html', property1="Entity", property2="Is located in", property3="Location", col1data=col1data, col2data=col2data, length=len(col1data))
    elif request.form['submit_button'] == 'home location':
        knows_query = """
            SELECT ?x ?y
            WHERE {
                ?x <http://www.semanticweb.org/win11/ontologies/2023/4/untitled-ontology-21#homeLocation> ?y
            }
        """
        qres = g.query(knows_query)
        for row in qres:
            col1 = str(row.x)
            col2 = str(row.y)
            col1data.append(col1[72:])
            col2data.append(col2[72:])
        return render_template('admin-table.html',  property1="Entity", property2="Home location", property3="Location", col1data=col1data, col2data=col2data, length=len(col1data))
    else:
        knows_query = """
            SELECT ?x ?y
            WHERE {
                ?x <http://www.semanticweb.org/win11/ontologies/2023/4/untitled-ontology-21#worksFor> ?y
            }
        """
        qres = g.query(knows_query)
        for row in qres:
            col1 = str(row.x)
            col2 = str(row.y)
            col1data.append(col1[72:])
            col2data.append(col2[72:])
        length = len(col1data)
        return render_template('admin-table.html',  property1="Person", property2="Works in", property3="Organisation", col1data=col1data, col2data=col2data, length=len(col1data))


@app.route('/worker-display/', methods=['GET', 'POST'])
@login_required
def worker_display():
    # username = session['username']
    username = "MigrantWorker1"
    prefix = "http://www.semanticweb.org/win11/ontologies/2023/4/untitled-ontology-21#"
    currentURI = prefix + username
    g = Graph()
    g.parse("RDFFile.rdf")
    #access name
    knows_query = """
        PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
        SELECT ?worker ?name
        WHERE {
        ?worker rdf:type <http://www.semanticweb.org/win11/ontologies/2023/4/untitled-ontology-21#Migrant-Worker> .
        ?worker <http://www.semanticweb.org/win11/ontologies/2023/4/untitled-ontology-21#Name> ?name .
        }
    """
    qres = g.query(knows_query)
    name = ""
    for row in qres:
        print(row)
        worker = str(row.worker)
        if currentURI == worker:
            name = str(row.name)
    #access blood group
    knows_query = """
        PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
        SELECT ?worker ?group
        WHERE {
        ?worker rdf:type <http://www.semanticweb.org/win11/ontologies/2023/4/untitled-ontology-21#Migrant-Worker> .
        ?worker <http://www.semanticweb.org/win11/ontologies/2023/4/untitled-ontology-21#Blood_Group> ?group .
        }
    """
    qres = g.query(knows_query)
    blood_group = ""
    for row in qres:
        print(row)
        worker = str(row.worker)
        if currentURI == worker:
            blood_group = str(row.group)
    #access phone number
    knows_query = """
        PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
        SELECT ?worker ?phone
        WHERE {
        ?worker rdf:type <http://www.semanticweb.org/win11/ontologies/2023/4/untitled-ontology-21#Migrant-Worker> .
        ?worker <http://www.semanticweb.org/win11/ontologies/2023/4/untitled-ontology-21#Phone-Number> ?phone .
        }
    """
    qres = g.query(knows_query)
    phone = ""
    for row in qres:
        print(row)
        worker = str(row.worker)
        if currentURI == worker:
            phone = str(row.phone)
    #access current location
    current_location = ""
    knows_query = """
        SELECT ?x ?y
        WHERE {
            ?x <http://www.semanticweb.org/win11/ontologies/2023/4/untitled-ontology-21#currentLocation> ?y
        }
    """
    qres = g.query(knows_query)
    for row in qres:
        uri = str(row.x)
        if uri == currentURI:
            curr = str(row.y)
            current_location = curr[72:]
    #access home location
    home_location = ""
    knows_query = """
        SELECT ?x ?y
        WHERE {
            ?x <http://www.semanticweb.org/win11/ontologies/2023/4/untitled-ontology-21#homeLocation> ?y
        }
    """
    qres = g.query(knows_query)
    for row in qres:
        uri = str(row.x)
        if uri == currentURI:
            curr = str(row.y)
            home_location = curr[72:]
    #access organisation
    organisation = ""
    knows_query = """
        SELECT ?x ?y
        WHERE {
            ?x <http://www.semanticweb.org/win11/ontologies/2023/4/untitled-ontology-21#worksFor> ?y
        }
    """
    qres = g.query(knows_query)
    for row in qres:
        uri = str(row.x)
        if uri == currentURI:
            curr = str(row.y)
            organisation = curr[72:]
    return render_template('worker-display.html', name=name, phone=phone, blood_group=blood_group, current_location=current_location, home_location=home_location, organisation=organisation)

@app.route('/worker-changeLocation/', methods=['GET', 'POST'])
@login_required
def worker_changeLocation():
    # username = session['username']
    username = "MigrantWorker1"
    prefix = "http://www.semanticweb.org/win11/ontologies/2023/4/untitled-ontology-21#"
    currentURI = prefix + username
    g = Graph()
    g.parse("RDFFile.rdf")
    g.update("""
        DELETE  {?s ?p ?o}
        WHERE { 
            <http://www.semanticweb.org/win11/ontologies/2023/4/untitled-ontology-21#MigrantWorker1> <http://www.semanticweb.org/win11/ontologies/2023/4/untitled-ontology-21#currentLocation> <http://www.semanticweb.org/win11/ontologies/2023/4/untitled-ontology-21#Location1> . 
            <http://www.semanticweb.org/win11/ontologies/2023/4/untitled-ontology-21#MigrantWorker1> <http://www.semanticweb.org/win11/ontologies/2023/4/untitled-ontology-21#currentLocation> <http://www.semanticweb.org/win11/ontologies/2023/4/untitled-ontology-21#Location2> . 
        }
    """)
    g.update("""
        INSERT DATA { <http://www.semanticweb.org/win11/ontologies/2023/4/untitled-ontology-21#MigrantWorker1> <http://www.semanticweb.org/win11/ontologies/2023/4/untitled-ontology-21#currentLocation> <http://www.semanticweb.org/win11/ontologies/2023/4/untitled-ontology-21#Location2> .}
    """)
    knows_query = """
        SELECT ?x ?y
        WHERE {
            ?x <http://www.semanticweb.org/win11/ontologies/2023/4/untitled-ontology-21#currentLocation> ?y
        }
    """
    qres = g.query(knows_query)
    for row in qres:
        uri = str(row.x)
        if uri == currentURI:
            curr = str(row.y)
            print(curr)
    return render_template('worker-changeLocation.html')


if __name__ == "__main__":
    app.run(debug=True)