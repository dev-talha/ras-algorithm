# RSA Chat System (Educational Project)

A simple educational project built with PHP that demonstrates the basic concepts of RSA Cryptography, including key generation, message encryption, and message decryption.

> ⚠️ This project is developed for learning and academic purposes only. It is not intended for production-level security.

---

## Features

- User Registration
- RSA Key Generation
- Public Key & Private Key Demonstration
- Message Encryption
- Message Decryption
- SQLite Database Support
- Simple and Beginner-Friendly Interface
- Pure PHP Implementation

---

## Technologies Used

- PHP
- SQLite
- HTML
- CSS
- JavaScript

---

## Project Objective

The main goal of this project is to help students understand the basic concepts of Public Key Cryptography using the RSA algorithm.

This project demonstrates:

- How RSA keys are generated
- How encryption works
- How decryption works
- The relationship between Public Key and Private Key

---

## Project Structure

```text
project/
│
├── database/
├── assets/
├── includes/
├── views/
├── index.php
└── README.md
```

---

## Requirements

Before running the project, make sure you have:

- PHP 8.0 or higher
- Modern Web Browser
  - Chrome
  - Firefox
  - Edge

No external database server is required because SQLite is used.

---

## Installation

### Step 1: Download the Project

Clone the repository:

```bash
https://github.com/dev-talha/ras-algorithm.git
```

Or download the ZIP file and extract it.

---

### Step 2: Open Terminal

Navigate to the project directory:

```bash
cd rsa-chat-system
```

---

### Step 3: Start PHP Development Server

Run:

```bash
php -S localhost:8000
```

---

### Step 4: Open in Browser

Visit:

```text
http://localhost:8000
```

The application should now be running.

---

## How It Works

### 1. User Registration

A user creates an account through the registration form.

---

### 2. RSA Key Generation

The system generates RSA values such as:

```text
p
q
n
d
```

Where:

- p and q are prime numbers
- n = p × q
- d is the private exponent

---

### 3. Public Key

The Public Key is used to encrypt messages.

It can be shared publicly.

---

### 4. Private Key

The Private Key is used to decrypt messages.

It should remain secret.

---

### 5. Encryption

The user enters a message.

The system converts the original message into encrypted data.

---

### 6. Decryption

The encrypted message is processed using the Private Key.

The original message is recovered successfully.

---

## Educational Notes

This project is intentionally simplified so students can understand RSA more easily.

Real-world RSA systems use:

- Very large prime numbers
- Strong cryptographic libraries
- Advanced security mechanisms

This project focuses on learning the RSA workflow rather than providing production-level security.

---

## Example RSA Concepts

```text
p = Prime Number
q = Prime Number

n = p × q

Public Key = (e, n)

Private Key = (d, n)
```

---

## Learning Outcomes

After studying this project, students should understand:

- Basic cryptography concepts
- Public Key Cryptography
- RSA key generation
- Encryption process
- Decryption process
- Secure communication principles

---

## Disclaimer

This project is created solely for educational and academic purposes.

Do not use this implementation to protect sensitive information in real-world applications.

---

## Author

Developed as an Educational RSA Cryptography Project for learning and academic demonstration.

---

## License

This project is free to use for educational purposes.
