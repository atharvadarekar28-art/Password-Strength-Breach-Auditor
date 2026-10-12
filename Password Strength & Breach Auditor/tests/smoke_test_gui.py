"""
PyQt6 Smoke Test.
Initializes the application, audits a password, validates widgets and tabs, and terminates cleanly.
"""

import sys
import os
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from PyQt6.QtWidgets import QApplication
from ui.app_qt import PasswordAuditorWindow

def test_qt_gui():
    print("Testing PyQt6 GUI initialization...")
    app = QApplication.instance()
    if not app:
        app = QApplication(sys.argv)

    window = PasswordAuditorWindow()
    window.show()
    app.processEvents()

    # Enter test password
    print("Setting test password: 'password'")
    window.pwd_input.setText("password")
    window.run_audit()

    # Wait for QThread to finish
    max_wait = 10
    start = time.time()
    while window.worker and window.worker.isRunning() and (time.time() - start < max_wait):
        app.processEvents()
        time.sleep(0.05)

    app.processEvents()
    print("Score displayed:", window.lbl_score.text())
    print("Status displayed:", window.lbl_status.text().encode("ascii", "replace").decode("ascii"))
    print("Alert displayed:", window.lbl_alert.text().encode("ascii", "replace").decode("ascii"))

    # Test tab switches
    for i in range(4):
        window.tabs.setCurrentIndex(i)
        app.processEvents()
        txt = window.tabs.tabText(i).encode("ascii", "replace").decode("ascii")
        print(f"Switched to Tab {i}: {txt}")

    # Test quick generator
    window.quick_generate()
    app.processEvents()
    print("Generated password:", window.pwd_input.text())

    # Test KAnonymityDialog
    from ui.app_qt import KAnonymityDialog
    dlg = KAnonymityDialog(window)
    dlg.show()
    app.processEvents()
    print("KAnonymityDialog initialized and rendered successfully!")
    dlg.close()

    window.close()
    app.processEvents()
    print("PyQt6 GUI smoke test passed successfully!")

if __name__ == "__main__":
    test_qt_gui()
