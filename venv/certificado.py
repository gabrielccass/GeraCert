import getpass
import datetime
import os
import tempfile
import subprocess
import tkinter as tk
from tkinter import messagebox
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import pkcs12, BestAvailableEncryption
from cryptography.hazmat.primitives.asymmetric import rsa
import win32net
import winreg

def obter_nome_completo_via_registro():
    try:
        chave = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Office\16.0\Common\Identity"
        )
        valor, _ = winreg.QueryValueEx(chave, "ADUserDisplayName")
        return valor
    except Exception:
        return None

def obter_nome_completo_via_dominio(matricula):
    try:
        info = win32net.NetUserGetInfo(None, matricula, 2)
        return info.get('full_name') or matricula
    except Exception:
        return matricula

def gerar_certificado():
    try:
        # Obter dados do usuário
        matricula = getpass.getuser()
        nome_completo = obter_nome_completo_via_registro() or obter_nome_completo_via_dominio(matricula)
        email = f"{matricula}@eletrobras.com.br"
        senha = "senha123"
        senha_bytes = senha.encode()
        dns_name = f"{nome_completo.replace(' ', '').lower()}.eletrobras.local"

        # Gerar chave privada
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        # Criar subject e issuer
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, nome_completo),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Eletrobras"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Usuário de Domínio"),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, email),
        ])

        issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "corp.eletrobras"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Eletrobras Autoridade Local"),
        ])

        # Criar certificado
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(dns_name)]),
                critical=False,
            )
            .sign(private_key, hashes.SHA256())
        )

        # Serializar para PFX com o nome completo como Friendly Name
        pfx_data = pkcs12.serialize_key_and_certificates(
            name=nome_completo.encode('utf-8'),
            key=private_key,
            cert=cert,
            cas=None,
            encryption_algorithm=BestAvailableEncryption(senha_bytes)
        )

        # Salvar arquivo PFX temporário
        temp_dir = tempfile.gettempdir()
        pfx_path = os.path.join(temp_dir, f"{matricula}_cert.pfx")
        with open(pfx_path, "wb") as f:
            f.write(pfx_data)

        # Instalar com certutil (sem admin)
        result = subprocess.run([
            "certutil", "-user",
            "-f", "-p", senha,
            "-importpfx", pfx_path
        ], capture_output=True, text=True)

        os.remove(pfx_path)  # Limpar

        if result.returncode != 0:
            raise Exception(result.stderr)

        messagebox.showinfo("Sucesso", f"Certificado para '{nome_completo}' instalado com sucesso!")

    except Exception as e:
        messagebox.showerror("Erro", f"Ocorreu um erro:\n{e}")

# === GUI ===
app = tk.Tk()
app.title("Instalador de Certificado")

frm = tk.Frame(app, padx=20, pady=20)
frm.pack()

matricula = getpass.getuser()
nome_completo = obter_nome_completo_via_registro() or obter_nome_completo_via_dominio(matricula)

tk.Label(frm, text="Usuário detectado:", font=("Arial", 10)).pack(anchor="w")
tk.Label(frm, text=nome_completo, font=("Arial", 12, "bold"), fg="blue").pack(anchor="w", pady=(0,10))
tk.Button(
    frm,
    text="Gerar e instalar certificado",
    font=("Arial", 11),
    command=gerar_certificado
).pack(pady=10)

app.mainloop()
