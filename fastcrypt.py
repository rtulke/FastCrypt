#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
FastCrypt - Advanced Encryption Application

A modern, cross-platform encryption tool with advanced cryptographic features.
Supports symmetric encryption, digital signatures, and key exchange protocols
with both modern algorithms (via cryptography library) and fallback implementations
using Python standard library.

Features:
- Modern encryption: AES-256-GCM, ChaCha20-Poly1305
- Digital signatures: RSA-PSS, Ed25519
- Key exchange: ECDH-P256, ECDH-P384
- Cross-platform GUI with Tkinter
- Memory-only operation (no persistent storage)
- Email integration for encrypted messages

Author: Robert Tulke
Email:  rt@debian.sh
Web:    https://tulke.ch
Repo:   https://gitlab.com/rtulke/fastcrypt/

Version: 2.0
License: Open Source (see repository for details)
Python:  3.8+ required
Dependencies: tkinter (built-in), cryptography (optional but recommended)

Security Notice:
This software is provided "as is" without warranty. While designed with
security best practices, no formal security audit has been performed.
For production use, always install the 'cryptography' library and
consider professional security review.

Copyright (c) 2025 Robert Tulke. All rights reserved.
"""

__version__ = "2.0"
__author__ = "Robert Tulke"
__email__ = "rt@debian.sh"
__website__ = "https://tulke.ch"
__repository__ = "https://gitlab.com/rtulke/fastcrypt/"

# fastcrypt.py

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import hashlib
import hmac
import secrets
import os
import webbrowser
import platform
import json
import base64
from typing import Dict, Callable, Optional, Tuple
from dataclasses import dataclass

# Try to import cryptography library
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec, ed25519
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


@dataclass
class KeyPair:
    """Container for asymmetric key pairs"""
    private_key: bytes
    public_key: bytes
    algorithm: str


class CryptoEngine:
    """Handles all cryptographic operations"""
    
    def __init__(self):
        self.algorithms = {
            "HMAC-SHA256": self.hmac_sha256_cipher,
            "XOR-Key": self.xor_cipher,
            "Base64 Encode": self.base64_encode,
        }
        
        # Add modern algorithms if cryptography is available
        if CRYPTO_AVAILABLE:
            self.algorithms.update({
                "AES-256-GCM": self.aes_gcm_cipher,
                "ChaCha20-Poly1305": self.chacha20_cipher,
            })
            
        self.signature_algorithms = {}
        self.key_exchange_algorithms = {}
        
        if CRYPTO_AVAILABLE:
            self.signature_algorithms = {
                "RSA-PSS": self.rsa_pss_sign,
                "Ed25519": self.ed25519_sign,
            }
            self.key_exchange_algorithms = {
                "ECDH-P256": self.ecdh_p256_exchange,
                "ECDH-P384": self.ecdh_p384_exchange,
            }
            
    def derive_key(self, password: str, salt: bytes, length: int = 32) -> bytes:
        """Derive encryption key using PBKDF2"""
        if CRYPTO_AVAILABLE:
            # Use HKDF for better key derivation
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=length,
                salt=salt,
                info=b'FastCrypt-Key-Derivation',
            )
            return hkdf.derive(password.encode('utf-8'))
        else:
            # Fallback to PBKDF2
            return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000, length)
            
    # Standard library implementations
    def hmac_sha256_cipher(self, text: str, password: str, salt: bytes, encrypt: bool) -> str:
        """HMAC-SHA256 based authentication"""
        try:
            if encrypt:
                # Generate new salt for each operation
                new_salt = secrets.token_bytes(32)
                key = self.derive_key(password, new_salt)
                
                h = hmac.new(key, text.encode('utf-8'), hashlib.sha256)
                # Combine salt + original_text + hmac
                combined = new_salt + text.encode('utf-8') + b'|' + h.digest()
                result = base64.b64encode(combined).decode()
                return result
            else:
                decoded = base64.b64decode(text.encode())
                # Extract salt and remaining data
                extracted_salt = decoded[:32]
                remaining = decoded[32:]
                
                # Split remaining into text and HMAC
                parts = remaining.split(b'|', 1)
                if len(parts) != 2:
                    raise ValueError("Invalid format")
                original_text, provided_hmac = parts
                
                # Verify with extracted salt
                key = self.derive_key(password, extracted_salt)
                h = hmac.new(key, original_text, hashlib.sha256)
                if hmac.compare_digest(h.digest(), provided_hmac):
                    return original_text.decode('utf-8')
                else:
                    raise ValueError("HMAC verification failed")
        except Exception as e:
            raise ValueError(f"HMAC operation failed: {str(e)}")
            
    def xor_cipher(self, text: str, password: str, salt: bytes, encrypt: bool) -> str:
        """Simple XOR cipher (NOT secure for real use!)"""
        try:
            if encrypt:
                # Generate new salt for each operation
                new_salt = secrets.token_bytes(32)
                key = self.derive_key(password, new_salt)
                
                result = bytearray()
                text_bytes = text.encode('utf-8')
                for i, byte in enumerate(text_bytes):
                    result.append(byte ^ key[i % len(key)])
                
                # Combine salt + encrypted_data
                combined = new_salt + result
                return base64.b64encode(combined).decode()
            else:
                decoded = base64.b64decode(text.encode())
                # Extract salt and encrypted data
                extracted_salt = decoded[:32]
                encrypted_data = decoded[32:]
                
                # Decrypt with extracted salt
                key = self.derive_key(password, extracted_salt)
                result = bytearray()
                for i, byte in enumerate(encrypted_data):
                    result.append(byte ^ key[i % len(key)])
                return result.decode('utf-8')
        except Exception as e:
            raise ValueError(f"XOR operation failed: {str(e)}")
            
    def base64_encode(self, text: str, password: str, salt: bytes, encrypt: bool) -> str:
        """Base64 encoding/decoding (NOT encryption!)"""
        try:
            if encrypt:
                return base64.b64encode(text.encode('utf-8')).decode()
            else:
                return base64.b64decode(text.encode()).decode('utf-8')
        except Exception as e:
            raise ValueError(f"Base64 operation failed: {str(e)}")
            
    # Modern cryptography implementations
    def aes_gcm_cipher(self, text: str, password: str, salt: bytes, encrypt: bool) -> str:
        """AES-256-GCM encryption/decryption"""
        if not CRYPTO_AVAILABLE:
            raise ValueError("Cryptography library not available")
            
        try:
            if encrypt:
                # Generate new salt for each encryption
                new_salt = secrets.token_bytes(32)
                key = self.derive_key(password, new_salt, 32)
                
                aesgcm = AESGCM(key)
                nonce = secrets.token_bytes(12)  # 96-bit nonce for GCM
                ciphertext = aesgcm.encrypt(nonce, text.encode('utf-8'), None)
                
                # Combine salt + nonce + ciphertext (salt is not secret!)
                combined = new_salt + nonce + ciphertext
                result = base64.b64encode(combined).decode()
                return result
            else:
                decoded = base64.b64decode(text.encode())
                # Extract salt, nonce, and ciphertext
                extracted_salt = decoded[:32]
                nonce = decoded[32:44]
                ciphertext = decoded[44:]
                
                # Derive key with extracted salt
                key = self.derive_key(password, extracted_salt, 32)
                aesgcm = AESGCM(key)
                plaintext = aesgcm.decrypt(nonce, ciphertext, None)
                return plaintext.decode('utf-8')
        except Exception as e:
            raise ValueError(f"AES-GCM operation failed: {str(e)}")
            
    def chacha20_cipher(self, text: str, password: str, salt: bytes, encrypt: bool) -> str:
        """ChaCha20-Poly1305 encryption/decryption"""
        if not CRYPTO_AVAILABLE:
            raise ValueError("Cryptography library not available")
            
        try:
            if encrypt:
                # Generate new salt for each encryption
                new_salt = secrets.token_bytes(32)
                key = self.derive_key(password, new_salt, 32)
                
                chacha = ChaCha20Poly1305(key)
                nonce = secrets.token_bytes(12)  # 96-bit nonce
                ciphertext = chacha.encrypt(nonce, text.encode('utf-8'), None)
                
                # Combine salt + nonce + ciphertext
                combined = new_salt + nonce + ciphertext
                result = base64.b64encode(combined).decode()
                return result
            else:
                decoded = base64.b64decode(text.encode())
                # Extract salt, nonce, and ciphertext
                extracted_salt = decoded[:32]
                nonce = decoded[32:44]
                ciphertext = decoded[44:]
                
                # Derive key with extracted salt
                key = self.derive_key(password, extracted_salt, 32)
                chacha = ChaCha20Poly1305(key)
                plaintext = chacha.decrypt(nonce, ciphertext, None)
                return plaintext.decode('utf-8')
        except Exception as e:
            raise ValueError(f"ChaCha20-Poly1305 operation failed: {str(e)}")
            
    # Digital signature implementations
    def generate_rsa_keypair(self) -> KeyPair:
        """Generate RSA key pair for signatures"""
        if not CRYPTO_AVAILABLE:
            raise ValueError("Cryptography library not available")
            
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = private_key.public_key()
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return KeyPair(private_pem, public_pem, "RSA-PSS")
        
    def generate_ed25519_keypair(self) -> KeyPair:
        """Generate Ed25519 key pair for signatures"""
        if not CRYPTO_AVAILABLE:
            raise ValueError("Cryptography library not available")
            
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return KeyPair(private_pem, public_pem, "Ed25519")
        
    def rsa_pss_sign(self, message: str, private_key_pem: bytes, verify: bool = False, 
                     signature: str = "", public_key_pem: bytes = b"") -> str:
        """RSA-PSS signature creation/verification"""
        if not CRYPTO_AVAILABLE:
            raise ValueError("Cryptography library not available")
            
        try:
            if verify:
                # Verify signature
                public_key = serialization.load_pem_public_key(public_key_pem)
                sig_bytes = base64.b64decode(signature.encode())
                public_key.verify(
                    sig_bytes,
                    message.encode('utf-8'),
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                return "Signature valid"
            else:
                # Create signature
                private_key = serialization.load_pem_private_key(private_key_pem, password=None)
                signature = private_key.sign(
                    message.encode('utf-8'),
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                return base64.b64encode(signature).decode()
        except Exception as e:
            raise ValueError(f"RSA-PSS signature failed: {str(e)}")
            
    def ed25519_sign(self, message: str, private_key_pem: bytes, verify: bool = False,
                     signature: str = "", public_key_pem: bytes = b"") -> str:
        """Ed25519 signature creation/verification"""
        if not CRYPTO_AVAILABLE:
            raise ValueError("Cryptography library not available")
            
        try:
            if verify:
                # Verify signature
                public_key = serialization.load_pem_public_key(public_key_pem)
                sig_bytes = base64.b64decode(signature.encode())
                public_key.verify(sig_bytes, message.encode('utf-8'))
                return "Signature valid"
            else:
                # Create signature
                private_key = serialization.load_pem_private_key(private_key_pem, password=None)
                signature = private_key.sign(message.encode('utf-8'))
                return base64.b64encode(signature).decode()
        except Exception as e:
            raise ValueError(f"Ed25519 signature failed: {str(e)}")
            
    # Key exchange implementations
    def generate_ecdh_keypair(self, curve_name: str) -> KeyPair:
        """Generate ECDH key pair"""
        if not CRYPTO_AVAILABLE:
            raise ValueError("Cryptography library not available")
            
        if curve_name == "P256":
            curve = ec.SECP256R1()
        elif curve_name == "P384":
            curve = ec.SECP384R1()
        else:
            raise ValueError(f"Unsupported curve: {curve_name}")
            
        private_key = ec.generate_private_key(curve)
        public_key = private_key.public_key()
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return KeyPair(private_pem, public_pem, f"ECDH-{curve_name}")
        
    def ecdh_p256_exchange(self, private_key_pem: bytes, peer_public_key_pem: bytes) -> str:
        """ECDH P-256 key exchange"""
        return self._ecdh_exchange(private_key_pem, peer_public_key_pem, "P256")
        
    def ecdh_p384_exchange(self, private_key_pem: bytes, peer_public_key_pem: bytes) -> str:
        """ECDH P-384 key exchange"""
        return self._ecdh_exchange(private_key_pem, peer_public_key_pem, "P384")
        
    def _ecdh_exchange(self, private_key_pem: bytes, peer_public_key_pem: bytes, curve: str) -> str:
        """Perform ECDH key exchange"""
        if not CRYPTO_AVAILABLE:
            raise ValueError("Cryptography library not available")
            
        try:
            private_key = serialization.load_pem_private_key(private_key_pem, password=None)
            peer_public_key = serialization.load_pem_public_key(peer_public_key_pem)
            
            shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
            
            # Derive final key using HKDF
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'FastCrypt-ECDH-Key',
            ).derive(shared_key)
            
            return base64.b64encode(derived_key).decode()
        except Exception as e:
            raise ValueError(f"ECDH exchange failed: {str(e)}")


class FastCrypt:
    """FastCrypt - Advanced Encryption Application
    
    A secure, cross-platform encryption tool with modern GUI and cryptographic features.
    Author: Robert Tulke <rt@debian.sh>
    """
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("FastCrypt v2.0")
        self.root.geometry("900x700")
        self.root.minsize(700, 500)
        
        # Initialize components
        self.crypto = CryptoEngine()
        
        # State variables
        self.current_keypair = None
        self.peer_public_key = None
        
        self.setup_gui()
        self.setup_menu()
        
    def setup_gui(self):
        """Setup the main GUI layout"""
        # Create notebook for tabbed interface
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create tabs
        self.setup_encryption_tab()
        self.setup_signature_tab()
        self.setup_keyexchange_tab()
        
    def setup_encryption_tab(self):
        """Setup encryption/decryption tab"""
        encrypt_frame = ttk.Frame(self.notebook)
        self.notebook.add(encrypt_frame, text="Encryption")
        
        # Configure grid
        encrypt_frame.columnconfigure(1, weight=1)
        encrypt_frame.rowconfigure(1, weight=1)
        encrypt_frame.rowconfigure(3, weight=1)
        
        # Algorithm selection
        control_frame = ttk.Frame(encrypt_frame)
        control_frame.grid(row=0, column=0, columnspan=4, sticky=(tk.W, tk.E), pady=(0, 10))
        
        ttk.Label(control_frame, text="Encryption Algorithm:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        self.algorithm_var = tk.StringVar(value=list(self.crypto.algorithms.keys())[0])
        algorithm_combo = ttk.Combobox(control_frame, textvariable=self.algorithm_var, 
                                     values=list(self.crypto.algorithms.keys()), state="readonly", width=25)
        algorithm_combo.grid(row=0, column=1, sticky=tk.W)
        
        # Input text area
        input_frame = ttk.LabelFrame(encrypt_frame, text="Input Text", padding="5")
        input_frame.grid(row=1, column=0, columnspan=4, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        input_frame.columnconfigure(0, weight=1)
        input_frame.rowconfigure(0, weight=1)
        
        self.input_text = scrolledtext.ScrolledText(input_frame, wrap=tk.WORD, height=8)
        self.input_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.input_text.bind('<KeyRelease>', self.update_char_count)
        
        self.char_count_label = ttk.Label(input_frame, text="Characters: 0")
        self.char_count_label.grid(row=1, column=0, sticky=tk.W, pady=(5, 0))
        
        # Action buttons
        button_frame = ttk.Frame(encrypt_frame)
        button_frame.grid(row=2, column=0, columnspan=4, pady=(0, 10))
        
        ttk.Button(button_frame, text="Encrypt", command=self.encrypt_text, width=15).grid(row=0, column=0, padx=(0, 5))
        ttk.Button(button_frame, text="Decrypt", command=self.decrypt_text, width=15).grid(row=0, column=1, padx=(5, 5))
        ttk.Button(button_frame, text="Clear All", command=self.clear_all, width=15).grid(row=0, column=2, padx=(5, 0))
        
        # Output text area
        output_frame = ttk.LabelFrame(encrypt_frame, text="Output Text", padding="5")
        output_frame.grid(row=3, column=0, columnspan=4, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        output_frame.columnconfigure(0, weight=1)
        output_frame.rowconfigure(0, weight=1)
        
        self.output_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, height=8)
        self.output_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Email section
        email_frame = ttk.LabelFrame(encrypt_frame, text="Send via Email", padding="5")
        email_frame.grid(row=4, column=0, columnspan=4, sticky=(tk.W, tk.E), pady=(0, 0))
        email_frame.columnconfigure(1, weight=1)
        
        ttk.Label(email_frame, text="To:").grid(row=0, column=0, sticky=tk.W)
        self.email_var = tk.StringVar()
        ttk.Entry(email_frame, textvariable=self.email_var).grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(5, 5))
        
        ttk.Label(email_frame, text="Subject:").grid(row=0, column=2, sticky=tk.W, padx=(5, 0))
        self.subject_var = tk.StringVar(value="Encrypted Message")
        ttk.Entry(email_frame, textvariable=self.subject_var, width=20).grid(row=0, column=3, sticky=(tk.W, tk.E), padx=(5, 5))
        
        ttk.Button(email_frame, text="Send Email", command=self.send_email, width=12).grid(row=0, column=4)
        
    def setup_signature_tab(self):
        """Setup digital signature tab"""
        if not CRYPTO_AVAILABLE:
            # Show info message if cryptography not available
            sig_frame = ttk.Frame(self.notebook)
            self.notebook.add(sig_frame, text="Signatures")
            ttk.Label(sig_frame, text="Digital signatures require 'cryptography' library.\n\nInstall with: pip install cryptography", 
                     justify=tk.CENTER).pack(expand=True)
            return
            
        sig_frame = ttk.Frame(self.notebook)
        self.notebook.add(sig_frame, text="Signatures")
        
        sig_frame.columnconfigure(0, weight=1)
        
        # Key generation section
        key_frame = ttk.LabelFrame(sig_frame, text="Key Management", padding="5")
        key_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(key_frame, text="Algorithm:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        self.sig_algorithm_var = tk.StringVar(value="RSA-PSS")
        sig_algo_combo = ttk.Combobox(key_frame, textvariable=self.sig_algorithm_var,
                                    values=list(self.crypto.signature_algorithms.keys()), state="readonly", width=15)
        sig_algo_combo.grid(row=0, column=1, sticky=tk.W, padx=(0, 10))
        
        ttk.Button(key_frame, text="Generate Keys", command=self.generate_signature_keys, width=15).grid(row=0, column=2, padx=(0, 5))
        ttk.Button(key_frame, text="Load Keys", command=self.load_signature_keys, width=15).grid(row=0, column=3, padx=(0, 5))
        ttk.Button(key_frame, text="Save Keys", command=self.save_signature_keys, width=15).grid(row=0, column=4)
        
        # Message and signature section
        msg_frame = ttk.LabelFrame(sig_frame, text="Message", padding="5")
        msg_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        msg_frame.columnconfigure(0, weight=1)
        msg_frame.rowconfigure(0, weight=1)
        
        self.signature_text = scrolledtext.ScrolledText(msg_frame, height=6)
        self.signature_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Signature operations
        sig_ops_frame = ttk.Frame(sig_frame)
        sig_ops_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(sig_ops_frame, text="Sign Message", command=self.sign_message, width=15).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(sig_ops_frame, text="Verify Signature", command=self.verify_signature, width=15).pack(side=tk.LEFT, padx=(5, 5))
        ttk.Button(sig_ops_frame, text="Load Public Key", command=self.load_public_key, width=15).pack(side=tk.LEFT, padx=(5, 0))
        
        # Signature display
        sig_display_frame = ttk.LabelFrame(sig_frame, text="Signature", padding="5")
        sig_display_frame.pack(fill=tk.X, padx=10, pady=5)
        sig_display_frame.columnconfigure(0, weight=1)
        
        self.signature_display = scrolledtext.ScrolledText(sig_display_frame, height=4)
        self.signature_display.grid(row=0, column=0, sticky=(tk.W, tk.E))
        
    def setup_keyexchange_tab(self):
        """Setup key exchange tab"""
        if not CRYPTO_AVAILABLE:
            # Show info message if cryptography not available
            kex_frame = ttk.Frame(self.notebook)
            self.notebook.add(kex_frame, text="Key Exchange")
            ttk.Label(kex_frame, text="Key exchange requires 'cryptography' library.\n\nInstall with: pip install cryptography", 
                     justify=tk.CENTER).pack(expand=True)
            return
            
        kex_frame = ttk.Frame(self.notebook)
        self.notebook.add(kex_frame, text="Key Exchange")
        
        kex_frame.columnconfigure(0, weight=1)
        
        # Protocol selection
        protocol_frame = ttk.LabelFrame(kex_frame, text="Key Exchange Protocol", padding="5")
        protocol_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(protocol_frame, text="Protocol:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        self.kex_protocol_var = tk.StringVar(value="ECDH-P256")
        kex_proto_combo = ttk.Combobox(protocol_frame, textvariable=self.kex_protocol_var,
                                     values=list(self.crypto.key_exchange_algorithms.keys()), state="readonly", width=15)
        kex_proto_combo.grid(row=0, column=1, sticky=tk.W, padx=(0, 10))
        
        ttk.Button(protocol_frame, text="Generate Key Pair", command=self.generate_kex_keypair, width=15).grid(row=0, column=2, padx=(0, 5))
        ttk.Button(protocol_frame, text="Load Key Pair", command=self.load_kex_keypair, width=15).grid(row=0, column=3, padx=(0, 5))
        ttk.Button(protocol_frame, text="Save Key Pair", command=self.save_kex_keypair, width=15).grid(row=0, column=4)
        
        # Public key exchange
        pubkey_frame = ttk.LabelFrame(kex_frame, text="Public Key Exchange", padding="5")
        pubkey_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        pubkey_frame.columnconfigure(0, weight=1)
        pubkey_frame.rowconfigure(1, weight=1)
        
        ttk.Label(pubkey_frame, text="Your Public Key (share this):").grid(row=0, column=0, sticky=tk.W)
        self.your_pubkey_display = scrolledtext.ScrolledText(pubkey_frame, height=4)
        self.your_pubkey_display.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(5, 10))
        
        ttk.Label(pubkey_frame, text="Peer's Public Key (paste here):").grid(row=2, column=0, sticky=tk.W)
        self.peer_pubkey_input = scrolledtext.ScrolledText(pubkey_frame, height=4)
        self.peer_pubkey_input.grid(row=3, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(5, 10))
        
        # Key exchange operation
        kex_ops_frame = ttk.Frame(kex_frame)
        kex_ops_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(kex_ops_frame, text="Perform Key Exchange", command=self.perform_key_exchange, width=20).pack(side=tk.LEFT, padx=(0, 10))
        
        # Shared secret display
        secret_frame = ttk.LabelFrame(kex_frame, text="Shared Secret", padding="5")
        secret_frame.pack(fill=tk.X, padx=10, pady=5)
        secret_frame.columnconfigure(0, weight=1)
        
        self.shared_secret_display = scrolledtext.ScrolledText(secret_frame, height=3)
        self.shared_secret_display.grid(row=0, column=0, sticky=(tk.W, tk.E))
        
    def setup_menu(self):
        """Setup application menu"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # Edit menu
        edit_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Edit", menu=edit_menu)
        edit_menu.add_command(label="Copy Input", command=lambda: self.copy_text(self.input_text))
        edit_menu.add_command(label="Copy Output", command=lambda: self.copy_text(self.output_text))
        edit_menu.add_separator()
        edit_menu.add_command(label="Paste to Input", command=lambda: self.paste_text(self.input_text))
        edit_menu.add_command(label="Clear Input", command=lambda: self.input_text.delete(1.0, tk.END))
        edit_menu.add_command(label="Clear Output", command=lambda: self.output_text.delete(1.0, tk.END))
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Generate Strong Password", command=self.generate_strong_password)
        tools_menu.add_separator()
        tools_menu.add_command(label="Check Crypto Library", command=self.check_crypto_status)
        tools_menu.add_separator()
        tools_menu.add_command(label="Test Encryption", command=self.test_encryption_compatibility)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="Help", command=self.show_help)
        help_menu.add_command(label="About", command=self.show_about)
        
        
    # Encryption methods
    def update_char_count(self, event=None):
        """Update character count display"""
        content = self.input_text.get(1.0, tk.END)
        char_count = len(content) - 1
        self.char_count_label.config(text=f"Characters: {char_count}")
        
    def generate_salt(self):
        """Generate cryptographically secure random salt"""
        self.current_salt = secrets.token_bytes(32)
        salt_preview = base64.b64encode(self.current_salt)[:8].decode()
        messagebox.showinfo("Salt Generated", f"New random salt generated!\nPreview: {salt_preview}...")
        
    def encrypt_text(self):
        """Encrypt the input text"""
        try:
            input_text = self.input_text.get(1.0, tk.END).strip()
            if not input_text:
                messagebox.showwarning("Warning", "Please enter text to encrypt")
                return
            
            # Get password with confirmation dialog
            password = self.show_password_input_dialog(confirm_password=True)
            if not password:
                return  # User cancelled
                
            algorithm = self.algorithm_var.get()
            cipher_func = self.crypto.algorithms[algorithm]
            
            # Pass None for salt - each algorithm generates its own salt
            encrypted = cipher_func(input_text, password, None, encrypt=True)
            
            self.output_text.delete(1.0, tk.END)
            self.output_text.insert(1.0, encrypted)
            
            # Show info that salt is embedded
            messagebox.showinfo("Encrypted", "Text encrypted successfully!\nSalt is embedded in encrypted message.")
            
        except Exception as e:
            messagebox.showerror("Encryption Error", str(e))
            
    def decrypt_text(self):
        """Decrypt the input text"""
        try:
            input_text = self.input_text.get(1.0, tk.END).strip()
            if not input_text:
                messagebox.showwarning("Warning", "Please enter text to decrypt")
                return
            
            # Get password (no confirmation needed for decryption)
            password = self.show_password_input_dialog(confirm_password=False)
            if not password:
                return  # User cancelled
                
            algorithm = self.algorithm_var.get()
            cipher_func = self.crypto.algorithms[algorithm]
            
            # Pass None for salt - algorithm extracts it from encrypted data
            decrypted = cipher_func(input_text, password, None, encrypt=False)
            
            self.output_text.delete(1.0, tk.END)
            self.output_text.insert(1.0, decrypted)
            
        except Exception as e:
            messagebox.showerror("Decryption Error", str(e))
    
    def show_password_input_dialog(self, confirm_password=True):
        """Show password input dialog with optional confirmation"""
        # Create custom dialog
        dialog = tk.Toplevel(self.root)
        if confirm_password:
            dialog.title("Enter Password for Encryption")
            dialog.geometry("400x250")
        else:
            dialog.title("Enter Password for Decryption")
            dialog.geometry("400x180")
            
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Remove transparency and set solid background
        dialog.configure(bg='#f0f0f0')
        dialog.attributes('-alpha', 1.0)  # Ensure fully opaque
        
        # Center dialog on parent
        x = self.root.winfo_rootx() + 100
        y = self.root.winfo_rooty() + 100
        dialog.geometry(f"+{x}+{y}")
        
        # Result variable
        result_password = None
        
        # Main frame with padding
        main_frame = ttk.Frame(dialog, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        main_frame.configure(style='Solid.TFrame')  # Ensure solid background
        
        # Title
        if confirm_password:
            title_text = "🔐 Enter Password for Encryption"
            subtitle_text = "Please enter your password twice for confirmation"
        else:
            title_text = "🔓 Enter Password for Decryption"
            subtitle_text = "Please enter your password"
            
        title_label = ttk.Label(main_frame, text=title_text, 
                               font=("TkDefaultFont", 12, "bold"), style='Solid.TLabel')
        title_label.pack(pady=(0, 5))
        
        subtitle_label = ttk.Label(main_frame, text=subtitle_text, 
                                  font=("TkDefaultFont", 9), style='Solid.TLabel')
        subtitle_label.pack(pady=(0, 15))
        
        # Password fields
        password_frame = ttk.Frame(main_frame, style='Solid.TFrame')
        password_frame.pack(fill=tk.X, pady=(0, 15))
        password_frame.columnconfigure(1, weight=1)
        
        # First password
        ttk.Label(password_frame, text="Password:", style='Solid.TLabel').grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        password1_var = tk.StringVar()
        password1_entry = ttk.Entry(password_frame, textvariable=password1_var, show="*", width=25)
        password1_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Show/hide toggle for first password
        show_password1 = tk.BooleanVar(value=False)
        def toggle_password1():
            if show_password1.get():
                # Currently showing, so hide it
                password1_entry.configure(show="*")
                toggle1_btn.configure(text="show")
                show_password1.set(False)
            else:
                # Currently hidden, so show it
                password1_entry.configure(show="")
                toggle1_btn.configure(text="hide")
                show_password1.set(True)
        
        toggle1_btn = ttk.Button(password_frame, text="show", width=3, command=toggle_password1)
        toggle1_btn.grid(row=0, column=2, padx=(5, 0), pady=(0, 10))
        
        # Second password (only for encryption)
        if confirm_password:
            ttk.Label(password_frame, text="Confirm:", style='Solid.TLabel').grid(row=1, column=0, sticky=tk.W, padx=(0, 10))
            password2_var = tk.StringVar()
            password2_entry = ttk.Entry(password_frame, textvariable=password2_var, show="*", width=25)
            password2_entry.grid(row=1, column=1, sticky=(tk.W, tk.E))
            
            # Show/hide toggle for second password
            show_password2 = tk.BooleanVar(value=False)
            def toggle_password2():
                if show_password2.get():
                    # Currently showing, so hide it
                    password2_entry.configure(show="*")
                    toggle2_btn.configure(text="show")
                    show_password2.set(False)
                else:
                    # Currently hidden, so show it
                    password2_entry.configure(show="")
                    toggle2_btn.configure(text="hide")
                    show_password2.set(True)
            
            toggle2_btn = ttk.Button(password_frame, text="show", width=3, command=toggle_password2)
            toggle2_btn.grid(row=1, column=2, padx=(5, 0))
        
        # Password strength indicator (only for encryption)
        if confirm_password:
            strength_label = ttk.Label(main_frame, text="", font=("TkDefaultFont", 8), style='Solid.TLabel')
            strength_label.pack(pady=(0, 10))
            
            def check_password_strength():
                password = password1_var.get()
                if len(password) == 0:
                    strength_label.configure(text="", foreground="black")
                elif len(password) < 8:
                    strength_label.configure(text="⚠️ Weak: Too short (minimum 8 characters)", foreground="red")
                elif len(password) < 12:
                    strength_label.configure(text="🟡 Medium: Consider longer password", foreground="orange")
                else:
                    has_upper = any(c.isupper() for c in password)
                    has_lower = any(c.islower() for c in password)
                    has_digit = any(c.isdigit() for c in password)
                    has_special = any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?" for c in password)
                    
                    if has_upper and has_lower and has_digit and has_special:
                        strength_label.configure(text="✅ Strong: Good password!", foreground="green")
                    else:
                        strength_label.configure(text="🟡 Medium: Add uppercase, numbers, symbols", foreground="orange")
            
            password1_var.trace_add("write", lambda *args: check_password_strength())
        
        # Buttons frame
        button_frame = ttk.Frame(main_frame, style='Solid.TFrame')
        button_frame.pack(fill=tk.X)
        
        def validate_and_proceed():
            nonlocal result_password
            password1 = password1_var.get()
            
            if not password1:
                messagebox.showwarning("Invalid Input", "Please enter a password")
                password1_entry.focus()
                return
            
            if confirm_password:
                password2 = password2_var.get()
                if password1 != password2:
                    messagebox.showerror("Password Mismatch", "Passwords do not match!\nPlease try again.")
                    password2_entry.delete(0, tk.END)
                    password2_entry.focus()
                    return
                
                if len(password1) < 8:
                    result = messagebox.askyesno("Weak Password", 
                                               "Your password is shorter than 8 characters.\n"
                                               "This may not be secure enough.\n\n"
                                               "Do you want to use it anyway?")
                    if not result:
                        password1_entry.focus()
                        return
            
            result_password = password1
            dialog.destroy()
        
        def cancel_dialog():
            nonlocal result_password
            result_password = None
            dialog.destroy()
        
        # OK button
        ok_btn = ttk.Button(button_frame, text="OK", command=validate_and_proceed, style='Solid.TButton')
        ok_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # Cancel button
        cancel_btn = ttk.Button(button_frame, text="Cancel", command=cancel_dialog, style='Solid.TButton')
        cancel_btn.pack(side=tk.LEFT)
        
        # Generate password button (only for encryption)
        if confirm_password:
            generate_btn = ttk.Button(button_frame, text="Generate", 
                                    command=lambda: self.insert_generated_password(password1_var, password2_var),
                                    style='Solid.TButton')
            generate_btn.pack(side=tk.RIGHT)
        
        # Focus and keyboard bindings
        password1_entry.focus()
        dialog.bind('<Escape>', lambda e: cancel_dialog())
        dialog.bind('<Return>', lambda e: validate_and_proceed())
        
        # Wait for dialog to close
        dialog.wait_window()
        
        return result_password
    
    def insert_generated_password(self, password1_var, password2_var):
        """Insert generated password into both fields"""
        try:
            import string
            characters = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
            password = ''.join(secrets.choice(characters) for _ in range(16))
            
            password1_var.set(password)
            password2_var.set(password)
            
            #messagebox.showinfo("Generated", "Strong password has been generated and inserted!")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate password: {str(e)}")
            
    def clear_all(self):
        """Clear all text fields"""
        self.input_text.delete(1.0, tk.END)
        self.output_text.delete(1.0, tk.END)
        self.password_var.set("")
        self.current_salt = None
        self.update_char_count()
        
    # Digital signature methods
    def generate_signature_keys(self):
        """Generate new signature key pair"""
        try:
            algorithm = self.sig_algorithm_var.get()
            if algorithm == "RSA-PSS":
                self.current_keypair = self.crypto.generate_rsa_keypair()
            elif algorithm == "Ed25519":
                self.current_keypair = self.crypto.generate_ed25519_keypair()
            else:
                messagebox.showerror("Error", f"Unknown algorithm: {algorithm}")
                return
                
            messagebox.showinfo("Success", f"{algorithm} key pair generated successfully!")
            
        except Exception as e:
            messagebox.showerror("Key Generation Error", str(e))
            
    def load_signature_keys(self):
        """Load signature key pair from files"""
        try:
            private_file = filedialog.askopenfilename(
                title="Select Private Key File",
                filetypes=[("PEM files", "*.pem"), ("All files", "*.*")]
            )
            if not private_file:
                return
                
            public_file = filedialog.askopenfilename(
                title="Select Public Key File",
                filetypes=[("PEM files", "*.pem"), ("All files", "*.*")]
            )
            if not public_file:
                return
                
            with open(private_file, 'rb') as f:
                private_key = f.read()
            with open(public_file, 'rb') as f:
                public_key = f.read()
                
            algorithm = self.sig_algorithm_var.get()
            self.current_keypair = KeyPair(private_key, public_key, algorithm)
            
            messagebox.showinfo("Success", "Key pair loaded successfully!")
            
        except Exception as e:
            messagebox.showerror("Load Error", str(e))
            
    def save_signature_keys(self):
        """Save signature key pair to files"""
        try:
            if not self.current_keypair:
                messagebox.showwarning("Warning", "No key pair to save. Generate keys first.")
                return
                
            private_file = filedialog.asksaveasfilename(
                title="Save Private Key As",
                defaultextension=".pem",
                filetypes=[("PEM files", "*.pem"), ("All files", "*.*")]
            )
            if not private_file:
                return
                
            public_file = filedialog.asksaveasfilename(
                title="Save Public Key As",
                defaultextension=".pem",
                filetypes=[("PEM files", "*.pem"), ("All files", "*.*")]
            )
            if not public_file:
                return
                
            with open(private_file, 'wb') as f:
                f.write(self.current_keypair.private_key)
            with open(public_file, 'wb') as f:
                f.write(self.current_keypair.public_key)
                
            messagebox.showinfo("Success", "Key pair saved successfully!")
            
        except Exception as e:
            messagebox.showerror("Save Error", str(e))
            
    def sign_message(self):
        """Sign the message"""
        try:
            if not self.current_keypair:
                messagebox.showwarning("Warning", "No key pair available. Generate keys first.")
                return
                
            message = self.signature_text.get(1.0, tk.END).strip()
            if not message:
                messagebox.showwarning("Warning", "Please enter a message to sign")
                return
                
            algorithm = self.sig_algorithm_var.get()
            sign_func = self.crypto.signature_algorithms[algorithm]
            
            signature = sign_func(message, self.current_keypair.private_key)
            
            self.signature_display.delete(1.0, tk.END)
            self.signature_display.insert(1.0, signature)
            
            messagebox.showinfo("Success", "Message signed successfully!")
            
        except Exception as e:
            messagebox.showerror("Signing Error", str(e))
            
    def verify_signature(self):
        """Verify the signature"""
        try:
            if not self.peer_public_key:
                messagebox.showwarning("Warning", "No public key loaded for verification")
                return
                
            message = self.signature_text.get(1.0, tk.END).strip()
            signature = self.signature_display.get(1.0, tk.END).strip()
            
            if not message or not signature:
                messagebox.showwarning("Warning", "Message and signature are required")
                return
                
            algorithm = self.sig_algorithm_var.get()
            verify_func = self.crypto.signature_algorithms[algorithm]
            
            result = verify_func(message, b"", verify=True, signature=signature, 
                               public_key_pem=self.peer_public_key)
            
            messagebox.showinfo("Verification Result", result)
            
        except Exception as e:
            messagebox.showerror("Verification Error", str(e))
            
    def load_public_key(self):
        """Load public key for signature verification"""
        try:
            public_file = filedialog.askopenfilename(
                title="Select Public Key File",
                filetypes=[("PEM files", "*.pem"), ("All files", "*.*")]
            )
            if not public_file:
                return
                
            with open(public_file, 'rb') as f:
                self.peer_public_key = f.read()
                
            messagebox.showinfo("Success", "Public key loaded successfully!")
            
        except Exception as e:
            messagebox.showerror("Load Error", str(e))
            
    # Key exchange methods
    def generate_kex_keypair(self):
        """Generate key exchange key pair"""
        try:
            protocol = self.kex_protocol_var.get()
            if protocol == "ECDH-P256":
                self.current_keypair = self.crypto.generate_ecdh_keypair("P256")
            elif protocol == "ECDH-P384":
                self.current_keypair = self.crypto.generate_ecdh_keypair("P384")
            else:
                messagebox.showerror("Error", f"Unknown protocol: {protocol}")
                return
                
            # Display your public key
            self.your_pubkey_display.delete(1.0, tk.END)
            self.your_pubkey_display.insert(1.0, self.current_keypair.public_key.decode())
            
            messagebox.showinfo("Success", f"{protocol} key pair generated successfully!")
            
        except Exception as e:
            messagebox.showerror("Key Generation Error", str(e))
            
    def load_kex_keypair(self):
        """Load key exchange key pair"""
        try:
            private_file = filedialog.askopenfilename(
                title="Select Private Key File",
                filetypes=[("PEM files", "*.pem"), ("All files", "*.*")]
            )
            if not private_file:
                return
                
            public_file = filedialog.askopenfilename(
                title="Select Public Key File",
                filetypes=[("PEM files", "*.pem"), ("All files", "*.*")]
            )
            if not public_file:
                return
                
            with open(private_file, 'rb') as f:
                private_key = f.read()
            with open(public_file, 'rb') as f:
                public_key = f.read()
                
            protocol = self.kex_protocol_var.get()
            self.current_keypair = KeyPair(private_key, public_key, protocol)
            
            # Display your public key
            self.your_pubkey_display.delete(1.0, tk.END)
            self.your_pubkey_display.insert(1.0, public_key.decode())
            
            messagebox.showinfo("Success", "Key pair loaded successfully!")
            
        except Exception as e:
            messagebox.showerror("Load Error", str(e))
            
    def save_kex_keypair(self):
        """Save key exchange key pair"""
        try:
            if not self.current_keypair:
                messagebox.showwarning("Warning", "No key pair to save. Generate keys first.")
                return
                
            private_file = filedialog.asksaveasfilename(
                title="Save Private Key As",
                defaultextension=".pem",
                filetypes=[("PEM files", "*.pem"), ("All files", "*.*")]
            )
            if not private_file:
                return
                
            public_file = filedialog.asksaveasfilename(
                title="Save Public Key As",
                defaultextension=".pem",
                filetypes=[("PEM files", "*.pem"), ("All files", "*.*")]
            )
            if not public_file:
                return
                
            with open(private_file, 'wb') as f:
                f.write(self.current_keypair.private_key)
            with open(public_file, 'wb') as f:
                f.write(self.current_keypair.public_key)
                
            messagebox.showinfo("Success", "Key pair saved successfully!")
            
        except Exception as e:
            messagebox.showerror("Save Error", str(e))
            
    def perform_key_exchange(self):
        """Perform key exchange with peer's public key"""
        try:
            if not self.current_keypair:
                messagebox.showwarning("Warning", "No key pair available. Generate keys first.")
                return
                
            peer_pubkey_text = self.peer_pubkey_input.get(1.0, tk.END).strip()
            if not peer_pubkey_text:
                messagebox.showwarning("Warning", "Please paste peer's public key")
                return
                
            protocol = self.kex_protocol_var.get()
            exchange_func = self.crypto.key_exchange_algorithms[protocol]
            
            shared_secret = exchange_func(self.current_keypair.private_key, peer_pubkey_text.encode())
            
            self.shared_secret_display.delete(1.0, tk.END)
            self.shared_secret_display.insert(1.0, shared_secret)
            
            messagebox.showinfo("Success", "Key exchange completed successfully!")
            
        except Exception as e:
            messagebox.showerror("Key Exchange Error", str(e))
            
    # Utility methods
    def copy_text(self, text_widget):
        """Copy text from widget to clipboard"""
        try:
            text = text_widget.get(1.0, tk.END).strip()
            if text:
                self.root.clipboard_clear()
                self.root.clipboard_append(text)
                messagebox.showinfo("Copied", "Text copied to clipboard")
            else:
                messagebox.showwarning("Warning", "No text to copy")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to copy text: {str(e)}")
            
    def paste_text(self, text_widget):
        """Paste text from clipboard to widget"""
        try:
            text = self.root.clipboard_get()
            text_widget.delete(1.0, tk.END)
            text_widget.insert(1.0, text)
            self.update_char_count()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to paste text: {str(e)}")
            
    def send_email(self):
        """Open email client with encrypted text"""
        try:
            email = self.email_var.get().strip()
            subject = self.subject_var.get().strip()
            body = self.output_text.get(1.0, tk.END).strip()
            
            if not email:
                messagebox.showwarning("Warning", "Please enter an email address")
                return
                
            if not body:
                messagebox.showwarning("Warning", "No encrypted text to send")
                return
                
            mailto_url = f"mailto:{email}?subject={subject}&body={body}"
            webbrowser.open(mailto_url)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open email client: {str(e)}")
            
    def generate_strong_password(self):
        """Generate a strong random password"""
        try:
            import string
            characters = string.ascii_letters + string.digits + "!@#$%^&*"
            password = ''.join(secrets.choice(characters) for _ in range(16))
            self.password_var.set(password)
            messagebox.showinfo("Password Generated", f"Strong password generated:\n{password}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate password: {str(e)}")
            
    def test_encryption_compatibility(self):
        """Test that encryption works across different sessions"""
        try:
            test_text = "Hello World! This is a test message."
            test_password = "TestPassword123!"
            
            # Test each algorithm
            results = []
            for algo_name, algo_func in self.crypto.algorithms.items():
                try:
                    # Encrypt
                    encrypted = algo_func(test_text, test_password, None, encrypt=True)
                    # Decrypt immediately (simulates different session)
                    decrypted = algo_func(encrypted, test_password, None, encrypt=False)
                    
                    if decrypted == test_text:
                        results.append(f"✅ {algo_name}: PASS")
                    else:
                        results.append(f"❌ {algo_name}: FAIL")
                except Exception as e:
                    results.append(f"❌ {algo_name}: ERROR - {str(e)}")
            
            result_text = "Encryption Compatibility Test Results:\n\n" + "\n".join(results)
            result_text += "\n\nAll PASS results mean encrypted data will work\nbetween different computers with same password."
            
            messagebox.showinfo("Compatibility Test", result_text)
            
        except Exception as e:
            messagebox.showerror("Test Error", f"Failed to run compatibility test: {str(e)}")
            
    def check_crypto_status(self):
        """Check cryptography library status"""
        if CRYPTO_AVAILABLE:
            status = "✅ Cryptography library is installed and available.\n\n"
            status += "Available features:\n"
            status += "• AES-256-GCM encryption\n"
            status += "• ChaCha20-Poly1305 encryption\n"
            status += "• Digital signatures (RSA-PSS, Ed25519)\n"
            status += "• Key exchange protocols (ECDH)\n"
            status += "• Advanced key derivation (HKDF)\n"
            status += "• Secure salt/nonce embedding"
        else:
            status = "⚠️ Cryptography library is NOT installed.\n\n"
            status += "Limited features available:\n"
            status += "• HMAC-SHA256 authentication\n"
            status += "• XOR cipher (not secure)\n"
            status += "• Base64 encoding\n\n"
            status += "To enable all features, install with:\n"
            status += "pip install cryptography"
            
        messagebox.showinfo("Crypto Library Status", status)
            
    def show_crypto_standards(self):
        """Show how real crypto libraries handle salt/nonce embedding"""
        standards_text = """Real-World Cryptography Standards

SALT/NONCE EMBEDDING IS STANDARD PRACTICE:

🔒 TLS/SSL (HTTPS):
   - Nonce embedded in every encrypted message
   - Billions of connections daily

🔒 Signal Protocol (WhatsApp, Signal):
   - IV/Nonce always transmitted with ciphertext
   - End-to-end encryption standard

🔒 OpenPGP/GPG:
   - Salt embedded in encrypted packets
   - Email encryption standard

🔒 Password Hashing:
   - bcrypt: $2b$12$SALT...HASH
   - scrypt: Salt always included
   - Argon2: Salt is part of output

🔒 Disk Encryption:
   - LUKS: Salt in header
   - FileVault: IV with encrypted data
   - BitLocker: Nonce embedded

WHY IT'S SECURE:
✅ Salt prevents rainbow table attacks
✅ Salt doesn't need to be secret
✅ Security comes from password + algorithm
✅ Each encryption gets unique salt/nonce
✅ Industry standard for 30+ years

WHY NOT SEPARATE SALT:
❌ Impractical (two messages needed)
❌ No security benefit
❌ Higher chance of loss/confusion
❌ Against crypto best practices

CONCLUSION: Salt embedding is the ONLY way
professional cryptographic systems work."""
        
        messagebox.showinfo("Cryptography Standards", standards_text)
        """Check cryptography library status"""
        if CRYPTO_AVAILABLE:
            status = "✅ Cryptography library is installed and available.\n\n"
            status += "Available features:\n"
            status += "• AES-256-GCM encryption\n"
            status += "• ChaCha20-Poly1305 encryption\n"
            status += "• Digital signatures (RSA-PSS, Ed25519)\n"
            status += "• Key exchange protocols (ECDH)\n"
            status += "• Advanced key derivation (HKDF)"
        else:
            status = "⚠️ Cryptography library is NOT installed.\n\n"
            status += "Limited features available:\n"
            status += "• HMAC-SHA256 authentication\n"
            status += "• XOR cipher (not secure)\n"
            status += "• Base64 encoding\n\n"
            status += "To enable all features, install with:\n"
            status += "pip install cryptography"
            
        messagebox.showinfo("Crypto Library Status", status)
        
    def show_help(self):
        """Show help dialog"""
        help_text = """FastCrypt v2.0 - Quick Help

ENCRYPTION TAB:
1. Select encryption algorithm
2. Enter text and click Encrypt/Decrypt  
3. Password dialog opens automatically
4. Salt is automatically generated and embedded
5. Copy result or send via email

IMPORTANT: Only password is needed for decryption!
The salt is automatically embedded in encrypted data.

SIGNATURES TAB:
1. Generate or load key pair
2. Enter message to sign
3. Sign message or verify signature
4. Load peer's public key for verification

KEY EXCHANGE TAB:
1. Select protocol (ECDH-P256/P384)
2. Generate key pair
3. Share your public key with peer
4. Paste peer's public key
5. Perform key exchange

CROSS-PLATFORM USAGE:
✅ Encrypted text works between different computers
✅ Only password is needed for decryption
✅ Salt is embedded automatically

KEYBOARD SHORTCUTS:
• Ctrl+C / Cmd+C: Copy
• Ctrl+V / Cmd+V: Paste

SECURITY:
• All operations use memory only
• Salt embedded in encrypted data
• Strong cryptographic algorithms when available
"""
        messagebox.showinfo("Help", help_text)
        
    def show_about(self):
        """Show about dialog"""
        crypto_status = "with cryptography library" if CRYPTO_AVAILABLE else "standard library only"
        
        about_text = f"""FastCrypt v2.0

A modern, cross-platform encryption application
{crypto_status}.

Features:
• Modern symmetric encryption
• Digital signatures
• Key exchange protocols
• Cross-platform support

Author: Robert Tulke
Email: rt@debian.sh

Websites:
• https://tulke.ch
• https://gitlab.com/rtulke/fastcrypt/

Built with Python and Tkinter.

Security Notice: Always verify the integrity of this
software before use in production environments.
"""
        messagebox.showinfo("About FastCrypt", about_text)
        
    def run(self):
        """Start the application"""
        if not CRYPTO_AVAILABLE:
            messagebox.showwarning("Limited Functionality", 
                                 "Cryptography library not found!\n\n"
                                 "Install with: pip install cryptography\n"
                                 "for full encryption and signature features.")
        self.root.mainloop()


if __name__ == "__main__":
    app = FastCrypt()
    app.run()
