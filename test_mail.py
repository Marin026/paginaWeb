import smtplib, ssl

smtp_server = "smtp.gmail.com"
port = 587
sender_email = "david22guerreroml@gmail.com"
password = "akkgsgpjgsqeqfyb"  # contraseña de aplicación
receiver_email = "juancuentsec@gmail.com"

message = """\
Subject: Prueba de Flask-Mail
zzzzzzzzzzzzz
Este es un correo de prueba desde Python.
"""

context = ssl.create_default_context()
with smtplib.SMTP(smtp_server, port) as server:
    server.starttls(context=context)
    server.login(sender_email, password)
    server.sendmail(sender_email, receiver_email, message)

print("✅ Correo enviado con éxito")
