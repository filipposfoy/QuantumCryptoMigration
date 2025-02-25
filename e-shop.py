import sys,os
from PyQt5.QtWidgets import QApplication, QMainWindow, QLabel, QLineEdit, QPushButton, QVBoxLayout, QWidget, QMessageBox, QListWidget
from Crypto.Cipher import DES
import hashlib 
import base64
import sqlite3
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Generate RSA keys and save to files
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    with open("private.pem", "wb") as private_file:
        private_file.write(private_key)
    
    with open("public.pem", "wb") as public_file:
        public_file.write(public_key)

# Load RSA public key for encryption
def load_rsa_public_key():
    with open("public.pem", "rb") as public_file:
        public_key = RSA.import_key(public_file.read())
    return public_key

# Load RSA private key for decryption (if needed later)
def load_rsa_private_key():
    with open("private.pem", "rb") as private_file:
        private_key = RSA.import_key(private_file.read())
    return private_key

# Encrypt data using RSA
def rsa_encrypt(public_key, data):
    cipher = PKCS1_OAEP.new(public_key)
    encrypted_data = cipher.encrypt(data.encode('utf-8'))
    return base64.b64encode(encrypted_data).decode('utf-8')

# Save encrypted order to the database
def save_order_with_rsa(user_id, product_id):
    # Load RSA public key
    public_key = load_rsa_public_key()
    print(public_key)

    # Encrypt order data
    encrypted_user_id = rsa_encrypt(public_key, str(user_id))
    encrypted_product_id = rsa_encrypt(public_key, str(product_id))

    # Save encrypted data to the database
    conn = sqlite3.connect('eshop.db')
    cursor = conn.cursor()

    # Ensure the 'encrypted_orders' table exists
    cursor.execute('''CREATE TABLE IF NOT EXISTS encrypted_orders (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        encrypted_user_id TEXT,
                        encrypted_product_id TEXT)''')

    # Insert encrypted order
    cursor.execute('INSERT INTO encrypted_orders (encrypted_user_id, encrypted_product_id) VALUES (?, ?)',
                   (encrypted_user_id, encrypted_product_id))
    conn.commit()
    conn.close()

    print("Order saved with RSA encryption!")

# Utility functions for encryption and hashing
def md5_hash(data):
    return hashlib.md5(data.encode()).hexdigest()

def aes_encrypt(key, plaintext):
    cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
    padded_text = plaintext + (16 - len(plaintext) % 16) * '\0'
    encrypted = cipher.encrypt(padded_text.encode('utf-8'))
    return base64.b64encode(encrypted).decode('utf-8')

def aes_decrypt(key, ciphertext):
    cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
    decrypted = cipher.decrypt(base64.b64decode(ciphertext))
    return decrypted.decode('utf-8').rstrip('\0')

def des_encrypt(key, plaintext):
    cipher = DES.new(key.encode('utf-8'), DES.MODE_ECB)
    padded_text = plaintext + (8 - len(plaintext) % 8) * '\0'  
    encrypted = cipher.encrypt(padded_text.encode('utf-8'))
    return base64.b64encode(encrypted).decode('utf-8')

def setup_database():
    conn = sqlite3.connect('eshop.db')
    cursor = conn.cursor()

    # Drop the existing 'products' table if it exists (to avoid schema mismatch)
    cursor.execute('DROP TABLE IF EXISTS products')

    # Users table
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE,
                        password TEXT)''')

    # Products table with name, description, and price
    cursor.execute('''CREATE TABLE IF NOT EXISTS products (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT,
                        description TEXT,
                        price REAL)''')

    # Orders table
    cursor.execute('''CREATE TABLE IF NOT EXISTS orders (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER,
                        product_id INTEGER,
                        FOREIGN KEY(user_id) REFERENCES users(id),
                        FOREIGN KEY(product_id) REFERENCES products(id))''')

    # Insert sample products with descriptions
    cursor.execute(""" 
    INSERT OR IGNORE INTO products (name, description, price) 
    VALUES 
    ('Product 1', 'High quality item.', 10.0),
    ('Product 2', 'Durable and long-lasting.', 20.0),
    ('Product 3', 'Great value for money.', 30.0),
    ('Product 4', 'Eco-friendly product.', 15.0),
    ('Product 5', 'Limited edition item.', 50.0)
    """)

    conn.commit()
    conn.close()


class EShopApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('E-Shop')
        self.setGeometry(100, 100, 600, 400)  # Set initial window size

        self.layout = QVBoxLayout()

        self.label = QLabel('Welcome to E-Shop! Login or Register:')
        self.layout.addWidget(self.label)

        self.username_input = QLineEdit(self)
        self.username_input.setPlaceholderText('Username')
        self.layout.addWidget(self.username_input)

        self.password_input = QLineEdit(self)
        self.password_input.setPlaceholderText('Password')
        self.password_input.setEchoMode(QLineEdit.Password)
        self.layout.addWidget(self.password_input)

        self.login_button = QPushButton('Login')
        self.login_button.clicked.connect(self.login)
        self.layout.addWidget(self.login_button)

        self.register_button = QPushButton('Register')
        self.register_button.clicked.connect(self.register)
        self.layout.addWidget(self.register_button)

        container = QWidget()
        container.setLayout(self.layout)
        self.setCentralWidget(container)

    def login(self):
        username = self.username_input.text()
        password = self.password_input.text()
        hashed_password = md5_hash(password)

        conn = sqlite3.connect('eshop.db')
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, hashed_password))
        user = cursor.fetchone()
        conn.close()

        if user:
            self.logged_in_user_id = user[0]  # Store user ID for future orders
            self.show_buy_page()
        else:
            QMessageBox.warning(self, 'Error', 'Invalid username or password.')

    def register(self):
        username = self.username_input.text()
        password = self.password_input.text()
        hashed_password = md5_hash(password)

        conn = sqlite3.connect('eshop.db')
        cursor = conn.cursor()

        try:
            cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
            conn.commit()
            QMessageBox.information(self, 'Success', 'Registration successful!')
        except sqlite3.IntegrityError:
            QMessageBox.warning(self, 'Error', 'Username already exists.')
        finally:
            conn.close()

    def show_buy_page(self):
        self.clear_layout(self.layout)

        self.label = QLabel('Select a product to buy:')
        self.layout.addWidget(self.label)

        # Display the list of products
        product_list = QListWidget(self)
        conn = sqlite3.connect('eshop.db')
        cursor = conn.cursor()
        cursor.execute('SELECT id, name, description, price FROM products')
        products = cursor.fetchall()
        conn.close()

        for product in products:
            product_list.addItem(f"{product[1]} - {product[2]} - ${product[3]:.2f}")

        self.layout.addWidget(product_list)

        # Add a Buy button
        view_bought_items_button = QPushButton('View Bought Items')
        view_bought_items_button.clicked.connect(self.show_bought_items)
        self.layout.addWidget(view_bought_items_button)

        buy_button = QPushButton('Buy Selected Product')
        buy_button.clicked.connect(lambda: self.buy_product(product_list))
        self.layout.addWidget(buy_button)

        container = QWidget()
        container.setLayout(self.layout)
        self.setCentralWidget(container)

    def buy_product(self, product_list):
        selected_item = product_list.currentItem()
        if selected_item:
            product_name = selected_item.text().split(' - ')[0]
            conn = sqlite3.connect('eshop.db')
            cursor = conn.cursor()

            # Find product id
            cursor.execute('SELECT id FROM products WHERE name = ?', (product_name,))
            product = cursor.fetchone()

            if product:
                self.selected_product_id = product[0]
                self.show_credit_card_page()
            conn.close()
        else:
            QMessageBox.warning(self, 'Error', 'Please select a product to buy.')
    

    def show_credit_card_page(self):
        self.clear_layout(self.layout)

        self.label = QLabel('Enter Credit Card Details:')
        self.layout.addWidget(self.label)

        # Credit card fields
        self.card_number_input = QLineEdit(self)
        self.card_number_input.setPlaceholderText('Card Number')
        self.layout.addWidget(self.card_number_input)

        self.expiration_input = QLineEdit(self)
        self.expiration_input.setPlaceholderText('Expiration Date (MM/YY)')
        self.layout.addWidget(self.expiration_input)

        self.cvv_input = QLineEdit(self)
        self.cvv_input.setPlaceholderText('CVV')
        self.layout.addWidget(self.cvv_input)

        # Submit button
        submit_button = QPushButton('Submit Payment')
        submit_button.clicked.connect(self.submit_payment)
        self.layout.addWidget(submit_button)

        container = QWidget()
        container.setLayout(self.layout)
        self.setCentralWidget(container)
    

    def show_bought_items(self):
        self.clear_layout(self.layout)

        self.label = QLabel('Your Bought Items:')
        self.layout.addWidget(self.label)

        # Fetch and display bought items
        bought_items_list = QListWidget(self)
        conn = sqlite3.connect('eshop.db')
        cursor = conn.cursor()
        cursor.execute('''SELECT products.name, products.description, products.price 
                          FROM orders 
                          JOIN products ON orders.product_id = products.id 
                          WHERE orders.user_id = ?''', (self.logged_in_user_id,))
        bought_items = cursor.fetchall()
        conn.close()

        for item in bought_items:
            bought_items_list.addItem(f"{item[0]} - {item[1]} - ${item[2]:.2f}")

        self.layout.addWidget(bought_items_list)

        # Back to Buy Page button
        back_button = QPushButton('Back to Buy Page')
        back_button.clicked.connect(self.show_buy_page)
        self.layout.addWidget(back_button)

        container = QWidget()
        container.setLayout(self.layout)
        self.setCentralWidget(container)

    def submit_payment(self):
        card_number = self.card_number_input.text()
        expiration = self.expiration_input.text()
        cvv = self.cvv_input.text()

        if not card_number or not expiration or not cvv:
            QMessageBox.warning(self, 'Error', 'Please enter all credit card details.')
            return

        key = '12345678'
        des_encrypt(key, card_number)
        des_encrypt(key, expiration)
        des_encrypt(key, cvv)

        QMessageBox.information(self, 'Success', 'Payment successful! Your order is confirmed.')
        save_order_with_rsa(self.logged_in_user_id, self.selected_product_id)
        self.show_buy_page()

    def clear_layout(self, layout):
        for i in reversed(range(layout.count())):
            widget = layout.itemAt(i).widget()
            if widget is not None:
                widget.deleteLater()

if __name__ == '__main__':
    setup_database()
    generate_rsa_keys()
    app = QApplication(sys.argv)
    ex = EShopApp()
    ex.show()
    sys.exit(app.exec_())