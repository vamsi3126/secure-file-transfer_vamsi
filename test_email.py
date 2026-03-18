import os
import sys
import traceback

os.environ["SMTP_EMAIL"] = "admin.email.dev@gmail.com"
os.environ["SMTP_PASSWORD"] = "xxim ikog oplh jcxc"
os.environ["SMTP_SERVER"] = "smtp.gmail.com"
os.environ["SMTP_PORT"] = "587"

try:
    from server import send_email_notification
    print("Sending test email to vamsigattikoppula@gmail.com...")
    send_email_notification(
        "vamsigattikoppula@gmail.com", 
        "http://localhost:5000/download?code=test&key=test", 
        "test_file.txt", 
        "2.5"
    )
    print("SUCCESS: Email sent successfully!")
except Exception as e:
    print(f"FAILED: Email could not be sent.")
    print("Error Details:")
    traceback.print_exc()
