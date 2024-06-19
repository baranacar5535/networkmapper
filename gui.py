
import sys
import threading
from PyQt5.QtCore import QUrl
from PyQt5.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QWidget
from PyQt5.QtWebEngineWidgets import QWebEngineView
from flask_socketio import SocketIO
import app  # Import your Flask app

# Start Flask server in a separate thread
def run_flask():
    socketio = SocketIO(app.app)
    socketio.run(app.app, host='127.0.0.1', port=5000, debug=False)

flask_thread = threading.Thread(target=run_flask)
flask_thread.daemon = True
flask_thread.start()

# PyQt application
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('S.P.I.D.E.R Network Scanner')
        self.setGeometry(100, 100, 1200, 800)

        self.browser = QWebEngineView()
        self.browser.setUrl(QUrl('http://127.0.0.1:5000'))

        self.layout = QVBoxLayout()
        self.layout.addWidget(self.browser)

        self.container = QWidget()
        self.container.setLayout(self.layout)
        self.setCentralWidget(self.container)

app = QApplication(sys.argv)
window = MainWindow()
window.show()
sys.exit(app.exec_())
