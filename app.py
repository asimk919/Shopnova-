import os
import json
from urllib.parse import quote

from flask import (
    Flask, render_template, redirect, url_for,
    request, session, flash
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user,
    logout_user, login_required, current_user
)
from flask_wtf.csrf import CSRFProtect
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from authlib.integrations.flask_client import OAuth

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")
if not app.config["SECRET_KEY"]:
    # Local testing only; set a private SECRET_KEY before deployment.
    app.config["SECRET_KEY"] = os.urandom(32).hex()

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///shopnova.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = (
    os.environ.get("COOKIE_SECURE", "0") == "1"
)

db = SQLAlchemy(app)
csrf = CSRFProtect(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "Order karne ke liye pehle login karein."

oauth = OAuth(app)
GOOGLE_ID = os.environ.get("GOOGLE_CLIENT_ID")
GOOGLE_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")

if GOOGLE_ID and GOOGLE_SECRET:
    oauth.register(
        name="google",
        client_id=GOOGLE_ID,
        client_secret=GOOGLE_SECRET,
        server_metadata_url=(
            "https://accounts.google.com/.well-known/openid-configuration"
        ),
        client_kwargs={"scope": "openid email profile"},
    )


UPLOAD_FOLDER = os.path.join(app.root_path, "static", "uploads")
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

WHATSAPP_NUMBER = os.environ.get("WHATSAPP_NUMBER", "")
PRODUCTS = [
    {"id": 1, "name": "Wireless Headphones", "price": 1800,
     "category": "Electronics",
     "image": "https://placehold.co/600x400/png?text=Headphones"},
    {"id": 2, "name": "Smart Watch", "price": 2500,
     "category": "Electronics",
     "image": "https://placehold.co/600x400/png?text=Smart+Watch"},
    {"id": 3, "name": "Casual T-Shirt", "price": 900,
     "category": "Fashion",
     "image": "https://placehold.co/600x400/png?text=T-Shirt"},
    {"id": 4, "name": "School Backpack", "price": 1400,
     "category": "Accessories",
     "image": "https://placehold.co/600x400/png?text=Backpack"},
    {"id": 5, "name": "Sports Shoes", "price": 3200,
     "category": "Fashion",
     "image": "https://placehold.co/600x400/png?text=Shoes"},
    {"id": 6, "name": "Desk Lamp", "price": 1100,
     "category": "Home",
     "image": "https://placehold.co/600x400/png?text=Desk+Lamp"},
]


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False, default="ShopNova User")
    email = db.Column(db.String(254), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=True)
    google_id = db.Column(db.String(255), unique=True, nullable=True)
    role = db.Column(db.String(20), nullable=False, default="customer")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return bool(self.password_hash) and check_password_hash(
            self.password_hash, password
        )


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


@app.context_processor
def common_data():
    return {"cart_count": sum(session.get("cart", {}).values())}


@app.route("/")
def home():
    q = request.args.get("q", "").strip().lower()
    products = [
        p for p in PRODUCTS
        if q in p["name"].lower() or q in p["category"].lower()
    ]
    return render_template("home.html", products=products, search=q)


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("home"))
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not name or len(name) > 80 or "@" not in email or len(email) > 254:
            flash("Apna sahi naam aur email likhein.")
        elif len(password) < 10:
            flash("Password kam az kam 10 characters ka rakhein.")
        elif User.query.filter_by(email=email).first():
            flash("Is email ka account pehle se mojood hai.")
        else:
            user = User(name=name, email=email)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            login_user(user)
            flash("ShopNova mein khush aamdeed!")
            return redirect(url_for("home"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("home"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for("home"))
        flash("Email ya password sahi nahi hai.")
    return render_template("login.html")


@app.route("/google-login")
def google_login():
    if not GOOGLE_ID or not GOOGLE_SECRET:
        flash("Google login abhi setup nahi hua. Email login use karein.")
        return redirect(url_for("login"))
    return oauth.google.authorize_redirect(url_for("google_callback", _external=True))


@app.route("/google-callback")
def google_callback():
    if not GOOGLE_ID or not GOOGLE_SECRET:
        return redirect(url_for("login"))
    token = oauth.google.authorize_access_token()
    info = token.get("userinfo")
    if not info or not info.get("email") or not info.get("email_verified"):
        flash("Verified Google email hasil nahi ho saka.")
        return redirect(url_for("login"))

    google_id = info["sub"]
    email = info["email"].strip().lower()
    user = User.query.filter_by(google_id=google_id).first()
    if not user:
        user = User.query.filter_by(email=email).first()
        if user and user.google_id and user.google_id != google_id:
            flash("Is email ke account ko link nahi kar sakte.")
            return redirect(url_for("login"))
        if not user:
            user = User(name=info.get("name", "ShopNova User")[:80], email=email)
            db.session.add(user)
        user.google_id = google_id
        db.session.commit()
    login_user(user)
    return redirect(url_for("home"))


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    session.pop("cart", None)
    flash("Aap logout ho gaye hain.")
    return redirect(url_for("home"))


@app.route("/add/<int:product_id>", methods=["POST"])
def add(product_id):
    if not any(p["id"] == product_id for p in PRODUCTS):
        return redirect(url_for("home"))
    cart = session.get("cart", {})
    key = str(product_id)
    cart[key] = min(int(cart.get(key, 0)) + 1, 99)
    session["cart"] = cart
    flash("Product cart mein add ho gaya.")
    return redirect(url_for("home"))


@app.route("/cart")
def view_cart():
    cart = session.get("cart", {})
    items, total = [], 0
    for p in PRODUCTS:
        qty = int(cart.get(str(p["id"]), 0))
        if qty > 0:
            subtotal = p["price"] * qty
            items.append({"product": p, "qty": qty, "subtotal": subtotal})
            total += subtotal
    return render_template("cart.html", items=items, total=total)


@app.route("/remove/<int:product_id>", methods=["POST"])
def remove(product_id):
    cart = session.get("cart", {})
    cart.pop(str(product_id), None)
    session["cart"] = cart
    return redirect(url_for("view_cart"))



@app.route("/checkout", methods=["GET", "POST"])
@login_required
def checkout():
    cart = session.get("cart", {})
    items = []
    total = 0

    for p in PRODUCTS:
        try:
            qty = max(0, min(int(cart.get(str(p["id"]), 0)), 99))
        except (TypeError, ValueError):
            qty = 0
        if qty:
            subtotal = p["price"] * qty
            items.append({
                "id": p["id"], "name": p["name"],
                "qty": qty, "price": p["price"],
                "subtotal": subtotal
            })
            total += subtotal

    if not items:
        flash("Checkout se pehle cart mein product add karein.")
        return redirect(url_for("view_cart"))

    if request.method == "GET":
        return render_template("checkout.html", total=total)

    customer = request.form.get("customer", "").strip()
    country = request.form.get("country", "").strip()
    phone_code = request.form.get("phone_code", "").strip()
    phone_local = request.form.get("phone", "").strip()
    phone = phone_code + " " + phone_local
    province = request.form.get("province", "").strip()
    city = request.form.get("city", "").strip()
    street = request.form.get("address", "").strip()
    postal_code = request.form.get("postal_code", "").strip()
    address = (
        f"{street}, {city}, {province}, {postal_code}, {country}"
    )
    method = request.form.get("payment_method", "").strip()
    ref = request.form.get("transaction_ref", "").strip()

    if (
        not customer or len(customer) > 100
        or not country or len(country) > 100
        or not phone_local or len(phone) > 30
        or not province or len(province) > 100
        or not city or len(city) > 100
        or not street or len(street) > 500
        or not postal_code or len(postal_code) > 20
        or len(address) > 850
    ):
        flash("Naam, phone aur delivery address sahi darj karein.")
        return render_template("checkout.html", total=total), 400

    if method not in ("JazzCash", "Easypaisa", "COD"):
        flash("Payment method select karein.")
        return render_template("checkout.html", total=total), 400

    if method in ("JazzCash", "Easypaisa") and not ref:
        flash("Manual payment ka transaction reference darj karein.")
        return render_template("checkout.html", total=total), 400

    new_order = Order(
        customer=customer,
        phone=phone,
        address=address,
        payment_method=method,
        transaction_ref=ref or None,
        items=json.dumps(items),
        total=total,
        status="Pending",
        payment_status="Unverified"
    )

    try:
        db.session.add(new_order)
        db.session.commit()
    except Exception:
        db.session.rollback()
        app.logger.exception("ShopNova order save nahi ho saka")
        flash("Order save nahi hua. Dobara koshish karein.")
        return render_template("checkout.html", total=total), 500

    session.pop("cart", None)
    return render_template(
        "order_success.html", order_id=new_order.id, method=method
    )


@app.route("/order", methods=["POST"])
@login_required
def order():
    if not WHATSAPP_NUMBER.isdigit() or len(WHATSAPP_NUMBER) < 10:
        flash("Seller ka WhatsApp number abhi configure nahi hua.")
        return redirect(url_for("view_cart"))
    cart = session.get("cart", {})
    lines = [
        "ShopNova order",
        "Customer: " + current_user.name,
        "Email: " + current_user.email,
    ]
    total = 0
    for p in PRODUCTS:
        qty = int(cart.get(str(p["id"]), 0))
        if qty > 0:
            subtotal = p["price"] * qty
            total += subtotal
            lines.append(f'{p["name"]} x {qty} = Rs. {subtotal}')
    if not total:
        return redirect(url_for("view_cart"))
    lines.append(f"Total (delivery excluded): Rs. {total}")
    lines.append("Please confirm stock, delivery charges and payment.")
    return redirect("https://wa.me/" + WHATSAPP_NUMBER + "?text=" + quote("\n".join(lines)))




@app.route("/admin/sellers", methods=["GET", "POST"])
@login_required
def admin_sellers():
    if current_user.role != "admin":
        return "Admin access required.", 403

    if request.method == "POST":
        try:
            application_id = int(request.form.get("application_id", "0"))
        except ValueError:
            return "Invalid application.", 400

        action = request.form.get("action", "")
        application = db.session.get(SellerApplication, application_id)

        if not application:
            flash("Application nahi mili.")
        elif action not in ("approve", "reject"):
            flash("Invalid action.")
        else:
            applicant = db.session.get(User, application.user_id)
            if not applicant:
                flash("User nahi mila.")
            elif application.status != "pending":
                flash("Ye application pehle hi process ho chuki hai.")
            elif action == "approve":
                applicant.role = "seller"
                application.status = "approved"
                db.session.commit()
                flash("Seller approve ho gaya.")
            else:
                application.status = "rejected"
                db.session.commit()
                flash("Seller application reject ho gayi.")

        return redirect(url_for("admin_sellers"))

    applications = SellerApplication.query.order_by(
        SellerApplication.id.desc()
    ).all()
    users = {
        u.id: u for u in User.query.filter(
            User.id.in_([a.user_id for a in applications])
        ).all()
    } if applications else {}

    return render_template(
        "admin_sellers.html",
        applications=applications,
        users=users
    )


@app.route("/seller/apply", methods=["GET", "POST"])
@login_required
def apply_seller():
    if current_user.role == "seller":
        flash("Aap pehle se seller hain.")
        return redirect(url_for("seller_dashboard"))

    application = SellerApplication.query.filter_by(
        user_id=current_user.id
    ).first()

    if request.method == "POST":
        if application and application.status == "pending":
            flash("Aapki seller application pehle hi pending hai.")
        elif application and application.status == "approved":
            flash("Aapki application approved hai. Dobara login karein.")
        else:
            if application:
                application.status = "pending"
            else:
                application = SellerApplication(
                    user_id=current_user.id,
                    status="pending"
                )
                db.session.add(application)
            db.session.commit()
            flash("Seller application submit ho gayi. Admin approval ka intezar karein.")
        return redirect(url_for("apply_seller"))

    return render_template("seller_apply.html", application=application)


@app.route("/seller", methods=["GET", "POST"])
@login_required
def seller_dashboard():
    if getattr(current_user, "role", "customer") != "seller":
        return "Seller access required.", 403

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        category = request.form.get("category", "").strip()

        try:
            price = float(request.form.get("price", "0"))
        except (TypeError, ValueError):
            price = 0

        photo = request.files.get("image")

        if not name or len(name) > 120 or not category or len(category) > 80:
            flash("Product name aur category sahi likhein.")
        elif price <= 0 or price > 100000000:
            flash("Product ki price sahi darj karein.")
        elif not photo or not photo.filename:
            flash("Product ki image select karein.")
        else:
            filename = secure_filename(photo.filename)
            extension = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

            if extension not in ALLOWED_EXTENSIONS:
                flash("Sirf PNG, JPG, JPEG ya WEBP image upload karein.")
            else:
                safe_name = os.urandom(8).hex() + "_" + filename
                photo.save(os.path.join(app.config["UPLOAD_FOLDER"], safe_name))

                product = SellerProduct(
                    seller_id=current_user.id,
                    name=name,
                    price=price,
                    category=category,
                    image="/static/uploads/" + safe_name
                )
                try:
                    db.session.add(product)
                    db.session.commit()
                    flash("Product successfully save ho gaya.")
                    return redirect(url_for("seller_dashboard"))
                except Exception:
                    db.session.rollback()
                    app.logger.exception("Seller product save failed")
                    flash("Product save nahi hua. Dobara koshish karein.")

    products = SellerProduct.query.filter_by(
        seller_id=current_user.id
    ).order_by(SellerProduct.id.desc()).all()

    return render_template("seller_dashboard.html", products=products)


@app.errorhandler(400)
def bad_request(error):
    return "Request invalid ya session expire ho gaya. Page refresh karke dobara try karein.", 400

class SellerApplication(db.Model):
    __tablename__ = "seller_applications"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, unique=True)
    status = db.Column(db.String(20), nullable=False, default="pending")
    created_at = db.Column(db.DateTime, nullable=False,
                           default=db.func.current_timestamp())


class SellerProduct(db.Model):
    __tablename__ = "seller_products"

    id = db.Column(db.Integer, primary_key=True)
    seller_id = db.Column(
        db.Integer, db.ForeignKey("user.id"), nullable=False
    )
    name = db.Column(db.String(120), nullable=False)
    price = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(80), nullable=False)
    image = db.Column(db.String(300), nullable=False)
    created_at = db.Column(
        db.DateTime, nullable=False,
        default=db.func.current_timestamp()
    )


class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    customer = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(30), nullable=False)
    address = db.Column(db.String(500), nullable=False)
    payment_method = db.Column(db.String(30), nullable=False)
    transaction_ref = db.Column(db.String(100), nullable=True)
    items = db.Column(db.Text, nullable=False)
    total = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(30), nullable=False, default="Pending")
    payment_status = db.Column(
        db.String(30), nullable=False, default="Unverified"
    )
    created_at = db.Column(
        db.DateTime, nullable=False,
        default=db.func.current_timestamp()
    )


with app.app_context():
    db.create_all()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
