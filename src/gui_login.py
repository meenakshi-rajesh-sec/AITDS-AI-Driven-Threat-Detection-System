#!/usr/bin/env python3
"""
AITDS - Login GUI
Secure authentication interface for the SOC dashboard
"""

import tkinter as tk
from tkinter import ttk, messagebox
import hashlib
import json
import os
from datetime import datetime

class LoginGUI:
    """Login interface with local authentication"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("AITDS - Secure Login")
        self.root.geometry("400x300")
        self.root.resizable(False, False)
        
        # Center window
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() // 2) - (400 // 2)
        y = (self.root.winfo_screenheight() // 2) - (300 // 2)
        self.root.geometry(f"400x300+{x}+{y}")
        
        # Authentication state
        self.authenticated = False
        self.username = None
        
        # User database (in production, use proper authentication)
        self.users_db = {
            "admin": self._hash_password("admin123"),
            "analyst": self._hash_password("analyst123"),
            "viewer": self._hash_password("viewer123")
        }
        
        # Apply dark theme
        self.setup_theme()
        self.create_widgets()
        
        # Bind Enter key
        self.root.bind('<Return>', lambda e: self.login())
    
    def _hash_password(self, password):
        """Hash password using SHA-256"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def setup_theme(self):
        """Apply dark SOC theme"""
        self.root.configure(bg='#1a1a1a')
        
        # Style configuration
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure styles
        style.configure('Dark.TFrame', background='#1a1a1a')
        style.configure('Dark.TLabel', background='#1a1a1a', foreground='#ffffff')
        style.configure('Dark.TEntry', fieldbackground='#2a2a2a', foreground='#ffffff', borderwidth=1)
        style.configure('Dark.TButton', background='#0066cc', foreground='#ffffff')
        style.map('Dark.TButton', background=[('active', '#0052a3')])
    
    def create_widgets(self):
        """Create login interface widgets"""
        # Main container
        main_frame = ttk.Frame(self.root, style='Dark.TFrame', padding="30")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = tk.Label(
            main_frame,
            text="🔐 AITDS SECURE ACCESS",
            font=("Arial", 16, "bold"),
            bg='#1a1a1a',
            fg='#00ff88'
        )
        title_label.pack(pady=(0, 20))
        
        # Subtitle
        subtitle_label = tk.Label(
            main_frame,
            text="AI Threat Detection System",
            font=("Arial", 10),
            bg='#1a1a1a',
            fg='#888888'
        )
        subtitle_label.pack(pady=(0, 30))
        
        # Username field
        username_label = tk.Label(
            main_frame,
            text="Username:",
            font=("Arial", 10),
            bg='#1a1a1a',
            fg='#ffffff'
        )
        username_label.pack(anchor=tk.W, pady=(0, 5))
        
        self.username_entry = tk.Entry(
            main_frame,
            font=("Arial", 10),
            bg='#2a2a2a',
            fg='#ffffff',
            insertbackground='#ffffff',
            relief=tk.FLAT,
            bd=5
        )
        self.username_entry.pack(fill=tk.X, pady=(0, 15))
        self.username_entry.focus()
        
        # Password field
        password_label = tk.Label(
            main_frame,
            text="Password:",
            font=("Arial", 10),
            bg='#1a1a1a',
            fg='#ffffff'
        )
        password_label.pack(anchor=tk.W, pady=(0, 5))
        
        self.password_entry = tk.Entry(
            main_frame,
            font=("Arial", 10),
            bg='#2a2a2a',
            fg='#ffffff',
            insertbackground='#ffffff',
            show="*",
            relief=tk.FLAT,
            bd=5
        )
        self.password_entry.pack(fill=tk.X, pady=(0, 20))
        
        # Login button
        self.login_button = tk.Button(
            main_frame,
            text="🚀 LOGIN",
            font=("Arial", 12, "bold"),
            bg='#0066cc',
            fg='#ffffff',
            activebackground='#0052a3',
            activeforeground='#ffffff',
            relief=tk.FLAT,
            bd=0,
            padx=20,
            pady=10,
            command=self.login
        )
        self.login_button.pack(fill=tk.X, pady=(0, 10))
        
        # Status label
        self.status_label = tk.Label(
            main_frame,
            text="Enter credentials to access SOC dashboard",
            font=("Arial", 9),
            bg='#1a1a1a',
            fg='#666666'
        )
        self.status_label.pack()
        
        # Footer info
        footer_frame = tk.Frame(main_frame, bg='#1a1a1a')
        footer_frame.pack(side=tk.BOTTOM, pady=(20, 0))
        
        info_label = tk.Label(
            footer_frame,
            text="Default: admin / admin123 | analyst / analyst123",
            font=("Arial", 8),
            bg='#1a1a1a',
            fg='#444444'
        )
        info_label.pack()
    
    def authenticate(self, username, password):
        """Authenticate user credentials"""
        if username in self.users_db:
            hashed_password = self._hash_password(password)
            if self.users_db[username] == hashed_password:
                return True
        return False
    
    def login(self):
        """Process login attempt"""
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        
        if not username or not password:
            self.show_error("Please enter both username and password")
            return
        
        if self.authenticate(username, password):
            self.authenticated = True
            self.username = username
            
            # Log successful login
            self.log_login(username, True)
            
            # Show success message
            self.status_label.config(
                text=f"✅ Authentication successful! Welcome {username}",
                fg='#00ff88'
            )
            
            # Close login window after delay
            self.root.after(1000, self.root.destroy)
            
        else:
            self.show_error("Invalid username or password")
            self.log_login(username, False)
    
    def show_error(self, message):
        """Display error message"""
        self.status_label.config(text=f"❌ {message}", fg='#ff4444')
        self.password_entry.delete(0, tk.END)
        self.password_entry.focus()
        
        # Shake animation for error
        self.shake_window()
    
    def shake_window(self):
        """Shake window for error feedback"""
        x = self.root.winfo_x()
        y = self.root.winfo_y()
        
        for _ in range(5):
            self.root.geometry(f"+{x+5}+{y}")
            self.root.update()
            self.root.after(50)
            self.root.geometry(f"+{x-5}+{y}")
            self.root.update()
            self.root.after(50)
        
        self.root.geometry(f"+{x}+{y}")
    
    def log_login(self, username, success):
        """Log login attempts"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'username': username,
            'success': success,
            'ip': 'localhost'  # In production, get real IP
        }
        
        # Create logs directory if it doesn't exist
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        logs_dir = os.path.join(project_root, 'logs')
        os.makedirs(logs_dir, exist_ok=True)
        
        # Write to log file
        log_file = os.path.join(logs_dir, 'auth.log')
        with open(log_file, 'a') as f:
            f.write(json.dumps(log_entry) + '\n')
    
    def run(self):
        """Start the login GUI"""
        self.root.mainloop()
        
        # Return authentication result
        return {
            'authenticated': self.authenticated,
            'username': self.username
        }

def main():
    """Main function for standalone execution"""
    login_gui = LoginGUI()
    result = login_gui.run()
    
    if result['authenticated']:
        print(f"✅ User {result['username']} authenticated successfully")
        print("🚀 Launching SOC dashboard...")
        
        # Here you would launch the main dashboard
        # For now, just print success
        return True
    else:
        print("❌ Authentication failed or cancelled")
        return False

if __name__ == "__main__":
    main()
